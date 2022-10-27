import * as _ from 'lodash';

export class Queue<T> {
  private _store: T[] = [];
  push(val: T) {
    this._store.push(val);
  }
  pop(): T | undefined {
    return this._store.shift();
  }
  clone(): Queue<T> {
    let clonedQueue = new Queue<T>();
    _.forEach(this._store, (item) => clonedQueue.push(item));
    return clonedQueue;
  }
  length(): Number {
    return this._store.length;
  }
}
