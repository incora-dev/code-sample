import { BaseReview } from '../base-review.interface';

export interface BatchGetReviewsParams {
  locationNames?: string[];
  pageSize?: number;
  pageToken?: string;
  orderBy?: string;
  ignoreRatingOnlyReviews?: boolean;
}

export interface BatchGetReviewsResponse {
  locationReviews: LocationReview[];
  nextPageToken?: string;
}

export interface LocationReview extends BaseReview {
  name: string;
  review: Review;
}

export interface Review {
  name: string,
  reviewId: string,
  reviewer: Reviewer,
  starRating: StarRating,
  comment: string,
  createTime: string,
  updateTime: string,
  reviewReply: ReviewReply,
}

interface Reviewer {
  profilePhotoUrl: string;
  displayName: string;
  isAnonymous: boolean;
}

export enum StarRating {
  STAR_RATING_UNSPECIFIED = 'STAR_RATING_UNSPECIFIED',
  ONE = 'ONE',
  TWO = 'TWO',
  THREE = 'THREE',
  FOUR = 'FOUR',
  FIVE = 'FIVE',
}

interface ReviewReply {
  comment: string;
  updateTime: string;
}
