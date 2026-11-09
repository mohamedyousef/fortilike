import { Controller, Get, Query, Param, Res, Logger } from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import { FilesService } from './files.service.js';

@Controller('files')
export class FilesController {
  private readonly logger = new Logger();
  constructor(private readonly files: FilesService) {}

  @Get(':name')
  get(@Param('name') name: string, @Query('id') id: string, @Res() reply: FastifyReply): void {
    const body = this.files.open(name);
    this.files.safeOpen(id);
    // df-ruleid: Log Forging
    this.logger.log(`opened ${name}`);
    // df-ruleid: Cross-Site Scripting: Reflected
    reply.send(name);
    // df-ok: Header Manipulation
    reply.header('cache-control', 'no-store');
    // df-ruleid: Header Manipulation
    reply.header('x-file', name);
    void body;
  }
}
