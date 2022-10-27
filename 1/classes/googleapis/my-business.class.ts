import {
  OAuth2Client,
  createAPIRequest,
  APIRequestContext,
} from 'googleapis-common';
import { GoogleApis } from 'googleapis';
import {
  Account,
  AccountsListResponse,
  BatchGetReviewsParams,
  BatchGetReviewsResponse,
  BatchGetParams,
  BatchGetResponse,
  Location,
  LocationsListResponse,
} from '../../interfaces/googleapis';

export class GoogleMyBusiness {
  private baseUrl: string = 'https://mybusiness.googleapis.com';

  public accounts: AccountsResource;
  public accountsAdmins: AccountsAdminsResource;
  public accountsInvitations: AccountsInvitationsResource;
  public accountsLocations: AccountsLocationsResource;
  public accountsLocationsAdmins: AccountsLocationsAdminsResource;
  public accountsLocationsFollowers: AccountsLocationsFollowersResource;
  public accountsLocationsLocalPosts: AccountsLocationsLocalPostsResource;
  public accountsLocationsMedia: AccountsLocationsMediaResource;
  public accountsLocationsMediaCustomers: AccountsLocationsMediaCustomersResource;
  public accountsLocationsQuestions: AccountsLocationsQuestionsResource;
  public accountsLocationsQuestionsAnswers: AccountsLocationsQuestionsAnswersResource;
  public accountsLocationsReviews: AccountsLocationsReviewsResource;
  public accountsLocationsVerifications: AccountsLocationsVerificationsResource;
  public attributes: AttributesResource;
  public categories: CategoriesResource;
  public chains: ChainsResource;
  public googleLocations: GoogleLocationsResource;

  constructor(auth: OAuth2Client, version: string = 'v4') {
    const versionUrl = `${this.baseUrl}/${version}`;

    this.accounts = new AccountsResource(auth, versionUrl);
    this.accountsAdmins = new AccountsAdminsResource(auth);
    this.accountsInvitations = new AccountsInvitationsResource(auth);
    this.accountsLocations = new AccountsLocationsResource(auth, versionUrl);
    this.accountsLocationsAdmins = new AccountsLocationsAdminsResource(auth);
    this.accountsLocationsFollowers = new AccountsLocationsFollowersResource(auth);
    this.accountsLocationsLocalPosts = new AccountsLocationsLocalPostsResource(auth);
    this.accountsLocationsMedia = new AccountsLocationsMediaResource(auth);
    this.accountsLocationsMediaCustomers = new AccountsLocationsMediaCustomersResource(auth);
    this.accountsLocationsQuestions = new AccountsLocationsQuestionsResource(auth);
    this.accountsLocationsQuestionsAnswers = new AccountsLocationsQuestionsAnswersResource(auth);
    this.accountsLocationsReviews = new AccountsLocationsReviewsResource(auth, versionUrl);
    this.accountsLocationsVerifications = new AccountsLocationsVerificationsResource(auth);
    this.attributes = new AttributesResource(auth);
    this.categories = new CategoriesResource(auth);
    this.chains = new ChainsResource(auth);
    this.googleLocations = new GoogleLocationsResource(auth);
  }
}

class Resource {
  private auth: OAuth2Client;
  private context: APIRequestContext;

  constructor(auth: OAuth2Client) {
    this.auth = auth;
    this.context = {
      _options: {},
      google: new GoogleApis(),
    }
  }

  protected buildRequestOptions(url, method, body?) {
    return {
      options: {
        url,
        method,
      },
      params: {
        auth: this.auth,
        requestBody: body,
      },
      requiredParams: [],
      pathParams: [],
      context: this.context,
    };
  }
}

class AccountsResource extends Resource {
  private baseUrl: string;

  constructor(auth: OAuth2Client, baseUrl: string) {
    super(auth);
    this.baseUrl = `${baseUrl}/accounts`;
  }

  public async list(): Promise<Account[]> {
    const options = this.buildRequestOptions(this.baseUrl, 'GET');
    const { data } = await createAPIRequest<AccountsListResponse>(options);

    return data.accounts;
  }
}

class AccountsAdminsResource extends Resource {
  // TO DO
}

class AccountsInvitationsResource extends Resource {
  // TO DO
}

class AccountsLocationsResource extends Resource {
  private baseUrl: string;

  constructor(auth: OAuth2Client, baseUrl: string) {
    super(auth);
    this.baseUrl = baseUrl;
  }

  public async list(accountName: string): Promise<LocationsListResponse> {
    const url = `${this.baseUrl}/${accountName}/locations`;
    const options = this.buildRequestOptions(url, 'GET');
    const { data } = await createAPIRequest<LocationsListResponse>(options);

    return data;
  }

  public async batchGet(accountName: string, body: BatchGetParams): Promise<BatchGetResponse> {
    const url = `${this.baseUrl}/${accountName}/locations:batchGet`;
    const options = this.buildRequestOptions(url, 'POST', body);
    const { data } = await createAPIRequest<BatchGetResponse>(options);

    return data;
  }

  public async batchGetReviews(accountName: string, body: BatchGetReviewsParams): Promise<BatchGetReviewsResponse> {
    const url = `${this.baseUrl}/${accountName}/locations:batchGetReviews`;
    const options = this.buildRequestOptions(url, 'POST', body);
    const { data } = await createAPIRequest<BatchGetReviewsResponse>(options);

    return data;
  }

  public async reportInsights(accountName: string, body): Promise<any> {
    const url = `${this.baseUrl}/${accountName}/locations:reportInsights`;
    const options = this.buildRequestOptions(url, 'POST', body);
    const { data } = await createAPIRequest<any>(options);

    return data;
  }
}

class AccountsLocationsAdminsResource extends Resource {
  // TO DO
}

class AccountsLocationsFollowersResource extends Resource {
  // TO DO
}

class AccountsLocationsLocalPostsResource extends Resource {
  // TO DO
}

class AccountsLocationsMediaResource extends Resource {
  // TO DO
}

class AccountsLocationsMediaCustomersResource extends Resource {
  // TO DO
}

class AccountsLocationsQuestionsResource extends Resource {
  // TO DO
}

class AccountsLocationsQuestionsAnswersResource extends Resource {
  // TO DO
}

class AccountsLocationsReviewsResource extends Resource {
  private baseUrl: string;

  constructor(auth: OAuth2Client, baseUrl: string) {
    super(auth);
    this.baseUrl = `${baseUrl}/accounts`;
  }

  public async list(): Promise<Account[]> {
    const options = this.buildRequestOptions(this.baseUrl, 'GET');
    const { data } = await createAPIRequest<AccountsListResponse>(options);

    return data.accounts;
  }
}

class AccountsLocationsVerificationsResource extends Resource {
  // TO DO
}

class AttributesResource extends Resource {
  // TO DO
}

class CategoriesResource extends Resource {
  // TO DO
}

class ChainsResource extends Resource {
  // TO DO
}

class GoogleLocationsResource extends Resource {
  // TO DO
}
