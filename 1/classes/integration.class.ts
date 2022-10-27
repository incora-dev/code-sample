import { Tokens, BaseReview } from '../interfaces';

export class Integration {
  protected scopes: string[];
  protected oauth2Client: any;

  public setCredentials(credentials: Tokens) {}
  public generateAuthUrl() {}
  public login(code: string): Promise<Tokens> {
    return null;
  };
  public async getReviews(): Promise<BaseReview[]> {
    return [];
  }
}
