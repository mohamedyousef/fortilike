import { readFileSync } from 'node:fs';
import { Injectable } from '@nestjs/common';

export interface BlobStore { read(name: string): string }

export class DiskStore implements BlobStore {
  read(name: string): string {
    // df-ruleid: Path Manipulation
    return readFileSync('/data/' + name, 'utf8');
  }
}

@Injectable()
export class FilesService {
  constructor(private readonly store: BlobStore) {}
  open(name: string): string {
    return this.store.read(name);
  }
  safeOpen(id: string): string {
    const n = Number(id);
    // df-ok: Path Manipulation
    return readFileSync(`/data/${n}.json`, 'utf8');
  }
}
