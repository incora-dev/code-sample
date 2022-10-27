import {
  BadRequestException,
  ConflictException,
  Injectable,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { ERROR_MESSAGES, PROVIDER_SELECTED_FIELDS } from '@shared/constants';
import { Provider } from '@shared/database/entities';
import { ProviderRepository } from '@shared/database/repositories';
import { PageDto, PageOptionsDto } from '@shared/dtos';
import {
  CreateProviderDto,
  PoolContractField,
  UpdateProviderDto,
} from './providers.dto';
import {
  dailyQueriesCapKey,
  projectedCapacityKey,
} from '@shared/redis/redis.keys';
import { RedisService } from '@shared/redis/redis.service';
import { ContractService } from '@shared/ethers/contract.service';

@Injectable()
export class ProvidersService {
  constructor(
    @InjectRepository(ProviderRepository)
    private readonly providerRepository: ProviderRepository,
    private readonly redisService: RedisService,
    private readonly contractService: ContractService,
  ) {}

  public getAll(
    pageOptions: PageOptionsDto<Provider>,
  ): Promise<PageDto<Provider>> {
    return this.providerRepository.findAll(pageOptions);
  }

  public async getById(id: string): Promise<Provider> {
    const provider = await this.providerRepository.findOne({
      where: { id },
      select: PROVIDER_SELECTED_FIELDS,
    });

    return provider;
  }

  public async create(
    createProviderData: CreateProviderDto,
  ): Promise<Provider> {
    try {
      const {
        name,
        projectedCapacity,
        dailyQueriesCap,
        queryConfirmationsCap,
        credentials,
      } = createProviderData;

      const { address } = await this.registerPool(createProviderData.name);

      const provider = await this.providerRepository.createProvider({
        name,
        address,
        projectedCapacity,
        dailyQueriesCap,
        queryConfirmationsCap,
        credentials,
      });

      await this.redisService.set(
        dailyQueriesCapKey(provider.id),
        String(dailyQueriesCap),
      );

      await this.redisService.set(
        projectedCapacityKey(provider.id),
        String(projectedCapacity),
      );

      return provider;
    } catch (error) {
      throw new ConflictException(ERROR_MESSAGES.PROVIDER_ALREADY_IN_USE);
    }
  }

  public async update(
    id: string,
    updateProviderData: UpdateProviderDto,
  ): Promise<Provider> {
    const provider = await this.providerRepository.findOne(id);
    if (!provider) {
      throw new BadRequestException(ERROR_MESSAGES.INCORRECT_ID_PROVIDED);
    }
    await this.providerRepository.update(id, updateProviderData);

    return this.providerRepository.findOne(id);
  }

  public async delete(id: string): Promise<boolean> {
    const provider = await this.providerRepository.findOne(id);
    if (!provider) {
      throw new BadRequestException(ERROR_MESSAGES.INCORRECT_ID_PROVIDED);
    }
    await this.providerRepository.softDelete(id);

    return true;
  }

  public async poolContract(poolName: string): Promise<PoolContractField> {
    const masterContract = await this.contractService.getMasterContract();
    const address = await masterContract.poolContract(poolName);

    return {
      address,
    };
  }

  public async refreshQueriesConfigs(): Promise<void> {
    const providers = await this.providerRepository.find({
      select: PROVIDER_SELECTED_FIELDS,
    });

    for (const provider of providers) {
      const {
        id,
        dailyQueriesCap,
        projectedCapacity,
      } = provider;
      this.redisService.set(dailyQueriesCapKey(id), String(dailyQueriesCap));

      this.redisService.set(
        projectedCapacityKey(id),
        String(projectedCapacity),
      );
    }
  }

  public async checkIfQueryExists(
    poolName: string,
    queryUrl: string,
  ): Promise<boolean> {
    const { address } = await this.providerRepository.findOne({
      where: {
        name: poolName,
      },
      select: ['address'],
    });

    const masterContract = await this.contractService.getProviderContract(
      address,
    );

    return masterContract.queryUrls(queryUrl);
  }

  private async registerPool(poolName: string): Promise<PoolContractField> {
    const masterContract = await this.contractService.getMasterContract();

    const transaction = await masterContract.registerPool(poolName);
    const transactionResult = await transaction.wait();
    const [log] = transactionResult?.logs;

    return {
      address: log?.address,
    };
  }
}
