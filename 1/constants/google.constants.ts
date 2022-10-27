export const SCOPES = [
  'https://www.googleapis.com/auth/business.manage',
];
export enum ACCESS_TYPES {
  ONLINE = 'online',
  OFFLINE = 'offline',
}
export const ENVIRONMENT_MAPPING = {
  'GOOGLE_CLIENT_ID': 'clientId',
  'GOOGLE_CLIENT_SECRET': 'clientSecret',
  'GOOGLE_REDIRECT_URL': 'redirectUrl',
};

export const RATING_MAP = {
  STAR_RATING_UNSPECIFIED: 0,
  ONE: 1,
  TWO: 2,
  THREE: 3,
  FOUR: 4,
  FIVE: 5,
}
