import { google } from 'googleapis';
import { OAuth2Client } from 'googleapis-common';
import { countries } from 'countries-list';
import { Integration } from './integration.class';
import { SCOPES, ACCESS_TYPES, RATING_MAP } from '../constants/google.constants';
import { GoogleAuthData, GoogleTokens, Location } from '../interfaces';
import { GoogleMyBusiness } from './googleapis/my-business.class';
import { Account } from '../interfaces/googleapis/account.interface';
import { BatchGetReviewsParams, LocationReview, StarRating } from '../interfaces/googleapis/location-review.interface';
import { SERVICES } from '../constants/services.constants';

export class GoogleIntegration extends Integration {
  private gmb: GoogleMyBusiness;
  private accounts: Account[];

  protected oauth2Client: OAuth2Client;

  constructor(
    authData: GoogleAuthData,
    refreshTokenListener?: (tokens: GoogleTokens) => void,
  ) {
    super();
    const { clientId, clientSecret, redirectUrl } = authData;
    this.oauth2Client = new google.auth.OAuth2(clientId, clientSecret, redirectUrl);
    if (refreshTokenListener) {
      this.oauth2Client.on('tokens', refreshTokenListener)
    };
    this.gmb = new GoogleMyBusiness(this.oauth2Client);
    this.scopes = SCOPES;
  }

  public setCredentials(tokens: GoogleTokens): void {
    this.oauth2Client.setCredentials(tokens);
  }

  public generateAuthUrl() {
    return this.oauth2Client.generateAuthUrl({
      access_type: ACCESS_TYPES.OFFLINE,
      scope: this.scopes,
    })
  }

  public async login(code: string): Promise<GoogleTokens> {
    const { tokens } = await this.oauth2Client.getToken(code);
    this.oauth2Client.setCredentials(tokens);

    return tokens as GoogleTokens;
  }

  private async getAccountReviews(accountName: string, params: BatchGetReviewsParams): Promise<LocationReview[]> {
    let pageToken;
    const reviews = [];
    do {
      if (pageToken) {
        params.pageToken = pageToken;
      }
      const {
        locationReviews,
        nextPageToken,
      } = await this.gmb.accountsLocations.batchGetReviews(accountName, params);

      pageToken = nextPageToken;
      if (locationReviews) {
        reviews.push(...locationReviews);
      }
    } while (pageToken);

    return reviews;
  }

  public async getAccountsList() {
    const accounts = await this.gmb.accounts.list();
    this.accounts = accounts;

    return accounts;
  }

  public async getReviews(): Promise<LocationReview[]> {
    await this.getAccountsList();

    const locations = await this.getLocationsList();
    const params: BatchGetReviewsParams = {
      locationNames: locations.map(location => location.name),
    };
    const reviews: LocationReview[] = [];
    for (const account of this.accounts) {
      const accountReviews = await this.getAccountReviews(account.name, params);
      reviews.push(...accountReviews);
    }

    return reviews;
  }

  public async getLocationsList(): Promise<Location[]> {
    await this.getAccountsList();

    const locations: Location[] = [];
    for (const account of this.accounts) {
      const { locations: accountLocations } = await this.gmb.accountsLocations.list(account.name);
      locations.push(...accountLocations);
    }

    return locations;
  }

  public getLocationIterator(accountName: string) {
    return new GoogleApiIterator(
      this.gmb.accountsLocations.list.bind(this.gmb.accountsLocations),
      'locations',
      [accountName],
    )
  }

  public getReviewIterator(accountName: string, params) {
    return new GoogleApiIterator(
      this.gmb.accountsLocations.batchGetReviews.bind(this.gmb.accountsLocations),
      'locationReviews',
      [accountName],
      params,
    )
  }

  public transformToLocationDto(locations: Location[], userId: string) {
    return locations.map((location) => ({
      user: { id: userId },
      source: SERVICES.GOOGLE,
      externalName: location.name,
      name: location.locationName,
      continent: countries[location.address.regionCode].continent,
      latitude: location.latlng ? location.latlng.latitude : null,
      longitude: location.latlng ? location.latlng.longitude: null,
      country: location.address.regionCode,
    }));
  }

  public transformToReviewDto(reviews: LocationReview[], locations: any[]) {
    return reviews.map((review) => {
      const location = locations.find(({ externalName }) => review.name === externalName);

      return {
        location,
        name: review.review.name,
        comment: review.review.comment,
        starRating: RATING_MAP[review.review.starRating],
        reviewer: review.review.reviewer.displayName,
        createTime: review.review.createTime,
        updateTime: review.review.updateTime,
      };
    });
  }
}

class GoogleApiIterator {
  private values: any[];
  private pageToken: string;
  private iterable: Function;
  private valuesKey: string;
  private args: any[];
  private params: { [key: string]: string };

  public hasNext: boolean = true;

  constructor(
    iterable: Function,
    valuesKey: string,
    args: any[] = [],
    params: { [key: string]: string } = {},
  ) {
    this.pageToken = null;
    this.iterable = iterable;
    this.valuesKey = valuesKey;
    this.args = args;
    this.params = params;
  }
  public async next() {
    if (!this.hasNext) return null;
    if (this.pageToken) {
      this.params.pageToken = this.pageToken;
    }
    const response = await this.iterable(...this.args, this.params);

    this.pageToken = response.nextPageToken;
    this.hasNext = Boolean(response.nextPageToken);
    this.values = response[this.valuesKey];

    return this.values;
  }
}
