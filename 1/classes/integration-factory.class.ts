import { GoogleIntegration } from './google.class';
import { SERVICES } from '../constants/services.constants';
import { ENVIRONMENT_MAPPING as GOOGLE_ENVIRONMENT_MAPPING } from '../constants/google.constants';
import { GoogleAuthData } from '../interfaces';

export class IntegrationFactory {
  private serviceName: SERVICES;
  private authData: object;
  private refreshTokenListener: (tokens) => void;

  constructor(
    serviceName: SERVICES,
    environmentData: object,
    refreshTokenListener?: (tokens) => void,
  ) {
    this.serviceName = serviceName;
    this.authData = this.transformEnvironmentToAuthData(environmentData);
    this.refreshTokenListener = refreshTokenListener;
  }

  getServiceInstance() {
    switch(this.serviceName) {
      case SERVICES.GOOGLE:
        return new GoogleIntegration(this.authData as GoogleAuthData, this.refreshTokenListener);
    }
  }

  static environmentKeys(serviceName: string) {
    switch (serviceName) {
      case SERVICES.GOOGLE:
        return Object.keys(GOOGLE_ENVIRONMENT_MAPPING);
    }
  }

  private transformEnvironmentToAuthData<T>(environment: T): T {
    let mapping = {};
    switch (this.serviceName) {
      case SERVICES.GOOGLE:
        mapping = GOOGLE_ENVIRONMENT_MAPPING;
        break;
    }

    return Object.keys(environment).reduce((authData, key) => ({
      ...authData,
      [mapping[key]]: environment[key],
    }), {} as T);
  }
}
