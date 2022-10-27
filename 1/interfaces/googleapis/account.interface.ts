export interface AccountsListResponse {
  accounts: Account[];
}

export interface Account {
  name: string;
  accountName: string;
  type: AccountType;
  role: AccountRole;
  state: AccountState;
  accountNumber: string;
  permissionLevel: PermissionLevel;
  organizationInfo: OrganizationInfo;
}

enum AccountType {
  ACCOUNT_TYPE_UNSPECIFIED = 'ACCOUNT_TYPE_UNSPECIFIED',
  PERSONAL = 'PERSONAL',
  LOCATION_GROUP = 'LOCATION_GROUP',
  USER_GROUP = 'USER_GROUP',
  ORGANIZATION = 'ORGANIZATION',
}

enum AccountRole {
  ACCOUNT_ROLE_UNSPECIFIED = 'ACCOUNT_ROLE_UNSPECIFIED',
  OWNER = 'OWNER',
  CO_OWNER = 'CO_OWNER',
  MANAGER = 'MANAGER',
  COMMUNITY_MANAGER = 'COMMUNITY_MANAGER',
}

interface AccountState {
  status: AccountStatus;
}

enum AccountStatus {
  ACCOUNT_STATUS_UNSPECIFIED = 'ACCOUNT_STATUS_UNSPECIFIED',
  VERIFIED = 'VERIFIED',
  UNVERIFIED = 'UNVERIFIED',
  VERIFICATION_REQUESTED = 'VERIFICATION_REQUESTED',
}

enum PermissionLevel {
  PERMISSION_LEVEL_UNSPECIFIED = 'PERMISSION_LEVEL_UNSPECIFIED',
  OWNER_LEVEL = 'OWNER_LEVEL',
  MEMBER_LEVEL = 'MEMBER_LEVEL',
}

interface OrganizationInfo {
  registeredDomain: string;
  postalAddress: PostalAddress,
  phoneNumber: string;
}

interface PostalAddress {
  revision: number;
  regionCode: string;
  languageCode: string;
  postalCode: string;
  sortingCode: string;
  administrativeArea: string;
  locality: string;
  sublocality: string;
  addressLines: string[];
  recipients: string[];
  organization: string;
}
