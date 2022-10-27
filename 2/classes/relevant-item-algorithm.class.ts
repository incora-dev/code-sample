import * as _ from 'lodash';

import { Queue } from '@lib/item-package-combination/classes/queue.class';
import { RelevantItem } from '@lib/item-package-combination/classes/relevant-item.class';
import { Group, Test } from '@best-price-app/interfaces';
import { SelectedTests } from '@lib/item-package-combination/interfaces/selected-tests.interface';
import { CommonUtils } from '@lib/item-package-combination/utils/common.utils';

export class RelevantItemGroupsAlgorithm {

  readonly BRUTE_LIMIT = 30;
  readonly DP_LIMIT = 20;
  readonly SIMILARUTY_LIMIT = 0.5;
  readonly DUPLICATION_LIMIT = 0.2;
  static readonly GROUP_SIMILARUTY_LIMIT = 0.2;

  public selectedTests: SelectedTests;
  public limit: number;
  private _bestItems: Array<RelevantItem> = [];

  constructor(selectedTests: SelectedTests, limit: number) {
    this.selectedTests = selectedTests;
    this.limit = limit;
  }

  static combineGroups(groups: Array<any>, testData: Array<Test>): Array<SelectedTests> {
    if (!groups.length) return [];
    let combinedGroups = [];
    let group = groups.shift();
    while (group) {
      if (groups.length) {
        const similarGroups = _.filter(groups, (el) => CommonUtils.calculateSimilarity(group, el) >= this.GROUP_SIMILARUTY_LIMIT);
        groups = _.difference(groups, similarGroups);
        similarGroups.push(group);
        combinedGroups.push(_.uniq(_.flattenDeep(similarGroups)));
      } else {
        combinedGroups.push(group);
      }
      group = groups.shift();
    }
    combinedGroups = _.map(combinedGroups, (groupIds) => {
      const groupData = _.map(groupIds, id => _.find(testData, test => test.id == id));

      return {
        ids: groupIds,
        data: groupData
      };
    });
  
    return combinedGroups;
  }

  public combineRelevantItems(relevantItems: Array<Array<RelevantItem>>): Array<RelevantItem> {
    relevantItems = relevantItems.sort((arr1, arr2) => arr1.length < arr2.length ? 1 : -1);
    let results = _.map(relevantItems.shift(), relevantItem => relevantItem);
    let nextRelevantItemArray = relevantItems.shift();
    while (nextRelevantItemArray) {
      const combinationArr = _.map(results, (item) => {
        const subCombinationArray = _.map(nextRelevantItemArray, nextItem => item.combine(nextItem, this.DUPLICATION_LIMIT))

        return this._getTopNItems(subCombinationArray, 1)[0];
      });
      results = [...combinationArr];
      nextRelevantItemArray = relevantItems.shift();
    }

    return this._getTopNItems(results, this.limit);
  }

  private _saveItemToResults(data: Object): void {
    this._bestItems.push(new RelevantItem(data));
  }

  private _isSimilarByBonuses(selectedItem: RelevantItem, relevantItems: Array<RelevantItem>): Boolean {
    let similarAlreadyExists = false;
    if (selectedItem.bonus.length) {
      similarAlreadyExists = _.some(relevantItems, topItem => _.isEqual(selectedItem.bonus, topItem.bonus));
    }

    return similarAlreadyExists;
  }

  private _isCompletelySame(group: Group): Boolean {
    return this.selectedTests.ids.length === group.totalTestsInGroupCount
      && this.selectedTests.ids.length === group.matchedTestsCount
      && !group.leftTestsCount && !group.countOfOtherTests;
  }

  private _isSamePlusBonus(group: Group): Boolean {
    return this.selectedTests.ids.length === group.matchedTestsCount
      && group.totalTestsInGroupCount > this.selectedTests.ids.length;
  }

  private _getTopNItems(relevantItems: Array<RelevantItem>, limit: Number): Array<RelevantItem> {
    const topItems = [];
    const sortedItems = _.sortBy(relevantItems, ['totalPrice']);
    _.forEach(sortedItems, (relevantItem) => {
      if (!this._isSimilarByBonuses(relevantItem, topItems)) topItems.push(relevantItem);
    });

    return _.take(topItems, limit);
  }

  private _addLeftTests(relevantItems: Array<RelevantItem>): void {
    _.forEach(relevantItems, (relevantItem) => {
      let leftTestIds = _.map(relevantItem.groups, (group) => group.testIds);
      leftTestIds = _.difference(this.selectedTests.ids, _.uniq(_.flattenDeep(leftTestIds)));
      const leftTestData = _.map(leftTestIds, id => _.find(this.selectedTests.data,test => test.id === id));
      relevantItem.save({ tests: leftTestData });
    });
  }

  solve(matchedGroups: Array<Group>, testForSearch: SelectedTests) {
    const matchedGroupsQueue = new Queue<Group>();
    _.forEach(matchedGroups, group => matchedGroupsQueue.push(group));
    if (!testForSearch.ids.length && !matchedGroupsQueue.length()) return [];
    if (!matchedGroupsQueue.length()) {
      this._saveItemToResults({ tests: testForSearch.data });
      return this._getTopNItems(this._bestItems, this.limit);
    }

    this._generateOptions(matchedGroupsQueue, testForSearch);

    return this._getTopNItems(this._bestItems, this.limit);
  }

  private _generateOptions(matchedGroupsQueue: Queue<Group>, testForSearch: SelectedTests) {
    if (testForSearch.ids.length <= this.DP_LIMIT) {
      return this.generateDP(matchedGroupsQueue, testForSearch);
    } else {
      if (matchedGroupsQueue.length() <= this.BRUTE_LIMIT) {
        return this.generateBrute(matchedGroupsQueue, testForSearch);
      } else {
        return this.generateGreedy(matchedGroupsQueue, testForSearch);
      }
    }
  }

  generateBrute(
    matchedGroupsQueue: Queue<Group>,
    testForSearch: SelectedTests,
    usedTests: Array<number> = [],
    selectedGroups: Array<Group> = []
  ): void {
    let group = matchedGroupsQueue.pop();
    while (group) {
      if (this._isSamePlusBonus(group) && !usedTests.length) {
        this._saveItemToResults({
          groups: [group],
          bonus: _.difference(group.testIds, this.selectedTests.ids)
        });
      } else {
        if (this._isCompletelySame(group)) {
          this._saveItemToResults({ groups: [group] });
        } else {
          if (!_.intersection(group.testIds, usedTests).length) {
            let idsForSearch = _.difference(testForSearch.ids, group.testIds);
            if (idsForSearch.length) {
              this.generateBrute(
                matchedGroupsQueue.clone(),
                {
                  ids: idsForSearch,
                  data: _.map(idsForSearch, (id) => _.find(testForSearch.data, { id: id }))
                },
                _.concat(usedTests, _.intersection(testForSearch.ids, group.testIds)),
                _.concat(selectedGroups, [group])
              );
            } else {
              testForSearch = {
                ids: [],
                data: []
              }
              usedTests = _.concat(usedTests, group.testIds);
              selectedGroups.push(group);
            }
          }
        }
      }
      group = matchedGroupsQueue.pop();
    }
    if (selectedGroups.length || testForSearch.data.length) {
      if (_.intersection(_.concat(usedTests, testForSearch.ids), this.selectedTests.ids).length === this.selectedTests.ids.length) {
        let allGroupTests = _.flattenDeep(_.map(selectedGroups, 'testIds'));
        this._saveItemToResults({
          groups: selectedGroups.length ? selectedGroups : [],
          tests: testForSearch.data.length ? testForSearch.data : [],
          bonus: _.difference(allGroupTests, this.selectedTests.ids)
        });
      }
    }
  }

  generateDP(matchedGroupsQueue: Queue<Group>, testForSearch: SelectedTests): void {
    const DP = [];
    for (let i = 0; i < (1 << testForSearch.ids.length); ++i) {
      DP.push([]);
    }
    DP[0].push(new RelevantItem());
    let group = matchedGroupsQueue.pop();
    while (group) {
      let groupMask = 0;
      testForSearch.ids.forEach(testId => {
        groupMask = 2 * groupMask + Number(group.testIds.includes(testId));
      });
      if (groupMask != 0) {
        for (let mask = 0; mask < (1 << testForSearch.ids.length); ++mask) {
          DP[mask].forEach(item => {
            if ((mask | groupMask) !== mask) {
              let newItem = item.clone();
              newItem.save({
                groups: [group],
                bonus: _.difference(group.testIds, this.selectedTests.ids)
              });
              let nextDP = DP[mask | groupMask];
              nextDP.push(newItem);
              if (nextDP.length > this.limit) {
                DP[mask | groupMask] = this._getTopNItems(nextDP, this.limit);
              }
            }
          })
        }
      }
      group = matchedGroupsQueue.pop();
    }
    _.forEach(DP, (DPItem) => this._addLeftTests(DPItem));
    this._bestItems = _.flatten(DP);
    this._bestItems = _.filter(this._bestItems, (relevantItem) => {
      const relevantItemTestIds = _.flattenDeep(_.map(relevantItem.groups, group => group.testIds));
      const relevantItemUniqueTestIds = _.uniq(relevantItemTestIds);

      return ((relevantItemTestIds.length - relevantItemUniqueTestIds.length) / this.selectedTests.ids.length <= this.DUPLICATION_LIMIT);
    });
  }

  generateGreedy(matchedGroupsQueue: Queue<Group>, testForSearch: SelectedTests): void {
    const newPacks = [];
    const relevantGroups = [];
    let group = matchedGroupsQueue.pop();
    relevantGroups.push(group);
    while (group) {
      if (newPacks.length < this.BRUTE_LIMIT) {
        let similarExist = false;
        _.forEach(newPacks, selectedGroup => {
          let intersectionSize = _.intersection(group.testIds, selectedGroup.testIds).length;
          if (intersectionSize / group.testIds.length > this.SIMILARUTY_LIMIT) {
            similarExist = true;
          }
        })
        if (!similarExist) {
          newPacks.push(group);
        }
      }
      group = matchedGroupsQueue.pop();
      relevantGroups.push(group);
    }
    _.forEach(relevantGroups, group => {
      if (newPacks.length < this.BRUTE_LIMIT && !newPacks.includes(group)) {
        newPacks.push(group);
      }
    });
    matchedGroupsQueue = new Queue<Group>();
    _.forEach(newPacks, (group) => matchedGroupsQueue.push(group));
    this.generateBrute(matchedGroupsQueue, testForSearch);
  }
}
