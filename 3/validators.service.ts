import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  Logger,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In } from 'typeorm';
import { ethers } from 'ethers';
import * as hash from 'object-hash';
import { AuthService } from '@shared/auth/auth.service';
import { MailService } from '@shared/mail/mail.service';
import { RedisService } from '@shared/redis/redis.service';
import {
  ERROR_MESSAGES,
  LINKS,
  NODE_SELECTED_FIELDS,
  QUERY_RESPONSE_TIMEOUT,
  USER_REJECTED_THE_TRANSACTION,
  VALIDATOR_IS_APPROVED_SELECTED_FIELDS,
  VALIDATOR_LOGIN_CONFIRM_SELECTED_FIELDS,
} from '@shared/constants';
import { Validator, Node, QueryUrl } from '@shared/database/entities';
import {
  ProviderRepository,
  QueryRepository,
  ValidatorRepository,
} from '@shared/database/repositories';
import { PageDto, PageOptionsDto, ValidatorPageOptionsDto } from '@shared/dtos';
import {
  AddValidationDataDto,
  CreateNodeFields,
  ConfirmLoginValidator,
  NodeAdminFields,
  NodeDataFields,
  UpdateValidatorDto,
  ValidateQueryDataDto,
  ValidatorContractField,
  ValidatorFields,
} from './validators.dto';
import { ICreateValidator, IUpdateValidator } from './validators.interface';
import { ITokenPayload } from '@shared/auth/auth.interface';
import { createHash } from '@shared/utils/hashing.util';
import { Roles, TokenType } from '@shared/auth/auth.enum';
import {
  loginHashKey,
  dailyQueriesCapKey,
  projectedCapacityKey,
} from '@shared/redis/redis.keys';
import CONFIG from '@application-config';
import { NodesStatus, ProviderNames } from './validators.enum';
import { NodeRepository } from '@shared/database/repositories/node.repository';
import { IAddQuery } from '@shared/third-party/third-party.interface';
import { ThirdPartyService } from '@shared/third-party/third-party.service';
import { ValidatorsGateway } from './validators.gateway';
import { decodeToken, getItem, wait } from '@shared/utils';
import { MorpheusCoreApiService } from '@shared/morpheus-core-api/morpheus-core-api.service';
import { HttpService } from '@nestjs/axios';
import { MailTemplateIds } from '@shared/mail/mail.variables.enum';
import { queryHandler } from './query-handler';
import { ContractService } from '@shared/ethers/contract.service';
import { getFeePerNode } from '@shared/utils/get-fee-node';

const { INVALID_HASH_PROVIDED } = ERROR_MESSAGES;
const { CONTRACT_ADDRESS, STAKED_AMOUNT } = CONFIG.POLYGONSCAN;
const { NO_REPLY_EMAIL } = CONFIG.SENDGRID;

@Injectable()
export class ValidatorsService {
  constructor(
    private readonly authService: AuthService,
    private readonly mailService: MailService,
    private readonly morpheusCoreApiService: MorpheusCoreApiService,
    private readonly redisService: RedisService,
    private readonly contractService: ContractService,
    @InjectRepository(ValidatorRepository)
    private readonly validatorRepository: ValidatorRepository,
    @InjectRepository(NodeRepository)
    private readonly nodeRepository: NodeRepository,
    @InjectRepository(ProviderRepository)
    private readonly providerRepository: ProviderRepository,
    @InjectRepository(QueryRepository)
    private readonly queryRepository: QueryRepository,
    private readonly thirdPartyService: ThirdPartyService,
    private readonly validatorsGateway: ValidatorsGateway,
    protected httpService: HttpService,
  ) {}

  public getAll(
    pageOptions: ValidatorPageOptionsDto,
  ): Promise<PageDto<Validator>> {
    return this.validatorRepository.findAll(pageOptions);
  }

  public getById(id: string): Promise<ValidatorFields> {
    return this.validatorRepository.findById(id);
  }

  public async login(email: string): Promise<boolean> {
    const hash = await createHash(email);

    this.redisService.set(loginHashKey(hash), email);
    const link = `${LINKS.LOGIN}${hash}`;

    await this.mailService.send({
      to: email,
      from: NO_REPLY_EMAIL,
      templateId: MailTemplateIds.VERIFY_YOUR_EMAIL,
      dynamicTemplateData: {
        verify_email_url: link,
        email,
      },
    });

    return true;
  }

  public async confirmLogin(hash: string): Promise<ConfirmLoginValidator> {
    const email = await this.redisService.get(loginHashKey(hash));
    await this.redisService.del(loginHashKey(hash));

    if (!email) {
      throw new ForbiddenException(INVALID_HASH_PROVIDED);
    }

    let validator = await this.validatorRepository.findOne({
      where: { email },
      select: VALIDATOR_LOGIN_CONFIRM_SELECTED_FIELDS,
    });

    if (!validator) {
      validator = await this.create({ email, name: email });
    }

    const { id, isApproved, reviewStatus } = validator;
    const tokenPayload = { id, role: Roles.VALIDATOR } as ITokenPayload;
    const { access, refresh } = await this.authService.generateSession(
      tokenPayload,
    );

    return {
      id,
      access,
      refresh,
      isApproved,
      reviewStatus,
    };
  }

  public async isApproved(token: string): Promise<boolean> {
    const { id } = decodeToken(token, TokenType.ACCESS);
    const { isApproved } = await this.validatorRepository.findOne({
      where: { id },
      select: VALIDATOR_IS_APPROVED_SELECTED_FIELDS,
    });

    return isApproved;
  }

  public async getAppTokens(accessToken: string) {
    const { id } = decodeToken(accessToken, TokenType.ACCESS);
    const tokenPayload = {
      id,
      role: Roles.APP_VALIDATOR,
    } as ITokenPayload;

    return this.authService.generateSession(tokenPayload);
  }

  public async update(
    id: string,
    updateValidatorData: UpdateValidatorDto,
  ): Promise<IUpdateValidator & Validator> {
    const validator = await this.validatorRepository.findOne(id);

    if (!validator) {
      throw new BadRequestException(ERROR_MESSAGES.INCORRECT_ID_PROVIDED);
    }

    await this.validatorRepository.update(id, updateValidatorData);

    return this.validatorRepository.findOne(id);
  }

  public async updateValidatorWallet(
    accessToken: string,
    wallet: string,
  ): Promise<Validator> {
    const { id } = decodeToken(accessToken, TokenType.ACCESS);
    return this.update(id, { wallet });
  }

  public async delete(id: string): Promise<boolean> {
    const validator = await this.validatorRepository.findOne(id);
    if (!validator) {
      throw new BadRequestException(ERROR_MESSAGES.INCORRECT_ID_PROVIDED);
    }
    await this.validatorRepository.softDelete(id);

    return true;
  }

  public async approveValidator(validatorId: string): Promise<boolean> {
    const { email, isApproved } = await this.validatorRepository.findOne({
      where: { id: validatorId },
      select: ['email', 'isApproved'],
    });

    await this.update(validatorId, { isApproved: !isApproved });

    await this.mailService.send({
      to: email,
      from: NO_REPLY_EMAIL,
      templateId: MailTemplateIds.KYC_SUCCESSFUL,
    });

    return true;
  }

  public async getNodeById(id: string): Promise<NodeAdminFields> {
    const node = await this.nodeRepository.findOne({
      where: { id },
      select: NODE_SELECTED_FIELDS,
    });

    const validatorContract = await this.contractService.getValidatorContract(
      node.address,
    );

    const earnings = await validatorContract.earnings();

    return {
      ...node,
      earnings: earnings.toString(),
    };
  }

  public getAllNodes(
    pageOptions: PageOptionsDto<Node>,
  ): Promise<PageDto<Node>> {
    return this.nodeRepository.findAll(pageOptions);
  }

  public async registerValidatorNode(
    token: string,
    createNodeData: CreateNodeFields,
  ): Promise<ValidatorContractField> {
    try {
      const { id: validatorId } = decodeToken(token, TokenType.ACCESS);
      const { providerIds = [], address, stakedAmount } = createNodeData;
      const amount = ethers.utils.parseEther(String(stakedAmount));

      const masterContract = await this.contractService.getMasterContract();

      const transaction = await masterContract.registerValidator(
        address,
        amount,
      );
      const tx = await transaction.wait();
      const validatorAddress = tx.logs[0].address;
      const transactionHash = tx.transactionHash;

      const nodesProviders = await this.nodeRepository.getProviders();
      const { providerId } = getItem(nodesProviders);

      providerIds.push(providerId);

      const providers = await this.providerRepository.find({
        id: In(providerIds),
      });

      await this.nodeRepository.createNode({
        validatorId,
        address: validatorAddress,
        providers,
        transactionHash,
      });

      return { address: validatorAddress };
    } catch (error) {
      throw new ConflictException(error);
    }
  }

  public async validatorContract(
    validatorAddress: string,
  ): Promise<ValidatorContractField> {
    try {
      const masterContract = await this.contractService.getMasterContract();

      return {
        address: await masterContract.validatorContract(validatorAddress),
      };
    } catch (error) {
      throw new BadRequestException(error);
    }
  }

  public async rewardValidator(): Promise<boolean> {
    const masterContract = await this.contractService.getMasterContract();
    const tokenContract = await this.contractService.getTokenContract();
    const amount = ethers.utils.parseEther(String(STAKED_AMOUNT));

    const validators = await this.validatorRepository.findValidatorsToReward();

    const transaction = await tokenContract.approve(CONTRACT_ADDRESS, amount);
    await transaction.wait();

    for (const validator of validators) {
      const [{ address }] = await this.nodeRepository.getAddress(
        validator.wallet,
      );

      const validatorContract = await this.contractService.getValidatorContract(
        address,
      );
      const stakeAmount = await validatorContract.stakedAmount();
      const feePerNode = getFeePerNode(stakeAmount);

      await masterContract.rewardValidator(validator.wallet, feePerNode);
    }

    return true;
  }

  public async closeNode(wallet: string): Promise<boolean> {
    try {
      const masterContract = await this.contractService.getMasterContract();

      const transaction = await masterContract.closeValidator(wallet);
      await transaction.wait();

      const [{ address }] = await this.nodeRepository.getAddress(wallet);

      const node = await this.nodeRepository.findOne({
        where: {
          address,
        },
        select: ['id'],
      });

      if (!node) {
        throw new BadRequestException(
          ERROR_MESSAGES.INCORRECT_ADDRESS_PROVIDED,
        );
      }

      await this.nodeRepository.update(node, { status: NodesStatus.DISABLED });

      return true;
    } catch (error) {
      throw new BadRequestException(error);
    }
  }

  public async withdrawValidatorEarnings(wallet: string): Promise<boolean> {
    try {
      const masterContract = await this.contractService.getMasterContract();

      const transaction = await masterContract.withdrawValidatorEarnings(
        wallet,
      );
      await transaction.wait();

      return true;
    } catch (error) {
      throw new BadRequestException(error);
    }
  }

  public async getNodeData(address: string): Promise<NodeDataFields> {
    try {
      const { transactionHash, status } = await this.nodeRepository.findOne({
        select: ['transactionHash', 'status'],
        where: { address },
      });

      const providers = await this.nodeRepository.getNodeProviders(address);

      const validatorContract = await this.contractService.getValidatorContract(
        address,
      );
      const stakedAmount = await validatorContract.stakedAmount();
      const validatedQueriesCount =
        await validatorContract.validatedQueriesCount();
      const earnings = await validatorContract.earnings();
      const isWidthrawEarnings = earnings <= 0;

      return {
        stakedAmount: stakedAmount.toString(),
        earnings: earnings.toString(),
        validatedQueriesCount: validatedQueriesCount.toString(),
        transactionHash,
        status,
        isWidthrawEarnings,
        providers,
      };
    } catch (error) {
      throw new BadRequestException(error);
    }
  }

  public async validateQuery(
    token: string,
    validateQueryData: ValidateQueryDataDto,
  ): Promise<boolean> {
    try {
      const { id: validatorId } = decodeToken(token, TokenType.ACCESS);
      const { queryUrl, providerName, shipmentTracker } = validateQueryData;
      const { credentials } = await this.providerRepository.findOne({
        where: { name: providerName },
        select: ['credentials'],
      });

      if (
        Object.values(ProviderNames).includes(providerName as ProviderNames)
      ) {
        const response = await queryHandler[providerName](
          queryUrl,
          credentials,
          shipmentTracker,
        );

        const hashedValue = hash(response, {
          excludeKeys: (key) => key === 'datetime',
        });
        await this.addValidation(validatorId, {
          ...validateQueryData,
          hashedValue,
        });
      }

      return true;
    } catch (error) {
      throw new BadRequestException(error);
    }
  }

  public async addValidation(
    validatorId: string,
    addValidationData: AddValidationDataDto,
  ): Promise<boolean> {
    try {
      const {
        validatorAddress,
        providerName,
        queryUrl,
        hashedValue,
        requestTimestamp,
      } = addValidationData;

      const result = await this.queryRepository.getOneQuery(requestTimestamp);
      const query = result[0];

      if (!query) {
        throw new BadRequestException(
          ERROR_MESSAGES.INCORRECT_QUERIES_PROVIDED,
        );
      }

      let transactionHash;

      try {
        transactionHash = await this.addValidationData(
          validatorAddress,
          providerName,
          queryUrl,
          query.shipmentTracker,
          requestTimestamp,
          hashedValue,
        );
      } catch (e) {
        Logger.log(e);
      }

      const hashedData = query.hashedData;
      hashedData.push(hashedValue);

      const transactionHashData = query.transactionHashData;
      transactionHashData.push(transactionHash);

      const { validators } = await this.queryRepository.getValidators(query.id);

      const newValidator = await this.validatorRepository.findOne({
        where: { id: validatorId },
      });

      validators.push(newValidator);
      await this.queryRepository.save({
        ...query,
        validators,
        hashedData,
        transactionHashData,
      });

      return true;
    } catch (error) {
      throw new BadRequestException(error);
    }
  }

  public async formationAndSendHashedTrackingData(): Promise<void> {
    try {
      const queries = await this.queryRepository.findAllChangesInTwoHours();
      const trackingData = [];

      queries.forEach(
        ({
          providerName,
          subProviderName,
          shipmentTracker,
          hashedData,
          createdAt,
          transactionHashData,
        }) => {
          trackingData.push({
            providerName,
            subProviderName,
            shipmentTracker,
            hashedValues: hashedData,
            requestTimestamp: `${new Date(createdAt).getTime()}`,
            transactionHashData,
          });
        },
      );

      if (trackingData.length) {
        await this.morpheusCoreApiService.sendHashedTrackingData(trackingData);
      }
    } catch (error) {
      throw new BadRequestException(error);
    }
  }

  public getAllQueries(
    pageOptions: PageOptionsDto<QueryUrl>,
  ): Promise<PageDto<QueryUrl>> {
    return this.queryRepository.findAll(pageOptions);
  }

  public getAllValidatorsValidatedQueries(
    token: string,
    pageOptions: PageOptionsDto<QueryUrl>,
  ): Promise<PageDto<QueryUrl>> {
    const { id: validatorId } = decodeToken(token, TokenType.ACCESS);

    return this.queryRepository.getAllValidatorsValidatedQueries(
      validatorId,
      pageOptions,
    );
  }

  public async addAndCheckQuery(queryData: IAddQuery) {
    try {
      const provider = await this.providerRepository.findOne({
        where: { name: queryData.providerName },
        select: ['id'],
      });

      if (!provider) {
        throw new BadRequestException(
          ERROR_MESSAGES.PROVIDER_MUST_BE_REGISTERED,
        );
      }

      const { id } = provider;

      const dailyQueriesCapCounter = await this.redisService.get(
        dailyQueriesCapKey(id),
      );
      const projectCapacityCounter = await this.redisService.get(
        projectedCapacityKey(id),
      );

      if (Number(dailyQueriesCapCounter) < 1) {
        throw new BadRequestException(
          ERROR_MESSAGES.DAILY_QUERIES_CAP_HAS_EXPIRED,
        );
      }

      if (Number(projectCapacityCounter) < 1) {
        throw new BadRequestException(
          ERROR_MESSAGES.PROJECT_CAPACITY_HAS_EXPIRED,
        );
      }

      const requestTimestamp = await this.thirdPartyService.addQuery(queryData);

      await this.validatorsGateway.sendQueryToClients({
        ...queryData,
        requestTimestamp,
      });

      await this.redisService.decr(dailyQueriesCapKey(id));

      const query = await this.queryRepository.findOne({
        where: { queryUrl: queryData.queryUrl },
      });

      if (!query) {
        await this.redisService.decr(projectedCapacityKey(id));
      }

      return true;
    } catch (error) {
      throw new BadRequestException(error);
    }
  }

  private create(
    data: ICreateValidator,
  ): Promise<ICreateValidator & Validator> {
    return this.validatorRepository.save(data);
  }

  private async addValidationData(
    validatorAddress,
    providerName,
    queryUrl,
    shipmentTracker,
    requestTimestamp,
    hashedValue,
  ): Promise<string> {
    const masterContract = await this.contractService.getMasterContract();

    const transaction = await masterContract.addValidation(
      validatorAddress,
      providerName,
      `${queryUrl}:${shipmentTracker}:${requestTimestamp}`,
      hashedValue,
    );

    const tx = await transaction.wait();
    return tx.transactionHash;
  }
}
