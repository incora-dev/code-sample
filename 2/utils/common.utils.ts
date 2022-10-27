import * as _ from 'lodash';

export class CommonUtils {
  static calculateSimilarity(arr1: Array<number>, arr2: Array<number>): number {
    return _.intersection(arr1, arr2).length / _.uniq([...arr1, ...arr2]).length
  }
}