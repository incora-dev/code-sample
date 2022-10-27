export interface BatchGetParams {
  locationNames?: string[];
}

export interface BatchGetResponse {
  locations: Location[];
}

export interface LocationsListResponse {
  locations: Location[];
  nextPageToken: string;
  totalSize: number;
}

export interface Location {
  name: string;
  languageCode: string;
  storeCode: string;
  locationName: string;
  primaryPhone: string;
  additionalPhones: string[];
  address: PostalAddress;
  primaryCategory: Category;
  additionalCategories: Category[];
  websiteUrl: string;
  regularHours: BusinessHours;
  specialHours: SpecialHours;
  serviceArea: ServiceAreaBusiness;
  locationKey: LocationKey;
  labels: string[];
  adWordsLocationExtensions: AdWordsLocationExtensions;
  latlng: LatLng;
  openInfo: OpenInfo;
  locationState: LocationState;
  attributes: Attribute[];
  metadata: Metadata;
  priceLists: PriceList[];
  profile: Profile;
  relationshipData: RelationshipData;
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

interface Category {
  displayName: string;
  categoryId: string;
  serviceTypes: ServiceType[];
}

interface ServiceType {
  serviceTypeId: string;
  displayName: string;
}

interface BusinessHours {
  periods: TimePeriod[];
}

interface TimePeriod {
  openDay: DayOfWeek;
  openTime: string;
  closeDay: DayOfWeek;
  closeTime: string;
}

enum DayOfWeek {
  DAY_OF_WEEK_UNSPECIFIED = 'DAY_OF_WEEK_UNSPECIFIED',
  MONDAY = 'MONDAY',
  TUESDAY = 'TUESDAY',
  WEDNESDAY = 'WEDNESDAY',
  THURSDAY = 'THURSDAY',
  FRIDAY = 'FRIDAY',
  SATURDAY = 'SATURDAY',
  SUNDAY = 'SUNDAY',
}

interface SpecialHours {
  specialHourPeriods: SpecialHourPeriod[];
}

interface SpecialHourPeriod {
  startDate: Date;
  openTime: string;
  endDate: Date;
  closeTime: string;
  isClosed: boolean;
}

interface Date {
  year: number;
  month: number;
  day: number;
}

interface ServiceAreaBusiness {
  businessType: BusinessType;
  radius: PointRadius;
  places: Places;
}

enum BusinessType {
  BUSINESS_TYPE_UNSPECIFIED = 'BUSINESS_TYPE_UNSPECIFIED',
  CUSTOMER_LOCATION_ONLY = 'CUSTOMER_LOCATION_ONLY',
  CUSTOMER_AND_BUSINESS_LOCATION = 'CUSTOMER_AND_BUSINESS_LOCATION',
}

interface PointRadius {
  latlng: LatLng;
  radiusKm: number;
}

interface LatLng {
  latitude: number;
  longitude: number;
}

interface Places {
  placeInfos: PlaceInfo[];
}

interface PlaceInfo {
  name: string;
  placeId: string;
}

interface LocationKey {
  plusPageId: string;
  placeId: string;
  explicitNoPlaceId: boolean;
  requestId: string;
}

interface AdWordsLocationExtensions {
  adPhone: string;
}

interface OpenInfo {
  status: OpenForBusiness;
  canReopen: boolean;
  openingDate: Date;
}

enum OpenForBusiness {
  OPEN_FOR_BUSINESS_UNSPECIFIED = 'OPEN_FOR_BUSINESS_UNSPECIFIED',
  OPEN = 'OPEN',
  CLOSED_PERMANENTLY = 'CLOSED_PERMANENTLY',
  CLOSED_TEMPORARILY = 'CLOSED_TEMPORARILY',
}

interface LocationState {
  isGoogleUpdated: boolean;
  isDuplicate: boolean;
  isSuspended: boolean;
  canUpdate: boolean;
  canDelete: boolean;
  isVerified: boolean;
  needsReverification: boolean;
  isPendingReview: boolean;
  isDisabled: boolean;
  isPublished: boolean;
  isDisconnected: boolean;
  isLocalPostApiDisabled: boolean;
  canModifyServiceList: boolean;
  canHaveFoodMenus: boolean;
  hasPendingEdits: boolean;
  hasPendingVerification: boolean;
}

interface Attribute {
  attributeId: string;
  valueType: AttributeValueType;
  values: string[];
  repeatedEnumValue: RepeatedEnumAttributeValue;
  urlValues: UrlAttributeValue[];
}

enum AttributeValueType {
  ATTRIBUTE_VALUE_TYPE_UNSPECIFIED = 'ATTRIBUTE_VALUE_TYPE_UNSPECIFIED',
  BOOL = 'BOOL',
  ENUM = 'ENUM',
  URL = 'URL',
  REPEATED_ENUM = 'REPEATED_ENUM',
}

interface RepeatedEnumAttributeValue {
  setValues: string[];
  unsetValues: string[];
}

interface UrlAttributeValue {
  url: string;
}

interface Metadata {
  duplicate: Duplicate;
  mapsUrl: string;
  newReviewUrl: string;
}

interface Duplicate {
  locationName: string;
  placeId: string;
  access: Access;
}

enum Access {
  ACCESS_UNSPECIFIED = 'ACCESS_UNSPECIFIED',
  ACCESS_UNKNOWN = 'ACCESS_UNKNOWN',
  ALLOWED = 'ALLOWED',
  INSUFFICIENT = 'INSUFFICIENT',
}

interface PriceList {
  priceListId: string;
  labels: Label[];
  sourceUrl: string;
  sections: Section[];
}

interface Label {
  displayName: string;
  description: string;
  languageCode: string;
}

interface Section {
  sectionId: string;
  labels: Label[];
  sectionType: SectionType;
  items: Item[];
}

enum SectionType {
  SECTION_TYPE_UNSPECIFIED = 'SECTION_TYPE_UNSPECIFIED',
  FOOD = 'FOOD',
  SERVICES = 'SERVICES',
}

interface Item {
  itemId: string;
  labels: Label[];
  price: Money;
}

interface Money {
  currencyCode: string;
  units: string;
  nanos: number;
}

interface Profile {
  description: string;
}

interface RelationshipData {
  parentChain: string;
}
