import { Injectable } from '@nestjs/common';

import {
  CreateEmailTemplateDto,
  EmailTemplateDto,
  UpdateEmailTemplateDto,
} from '../dto';
import { PrismaService } from '../../prisma';

@Injectable()
export class EmailTemplateService {
  constructor(private readonly prisma: PrismaService) {}

  async getAllTemplates(): Promise<EmailTemplateDto[]> {
    return this.prisma.emailTemplate.findMany();
  }

  async getTemplateById(id: string) {
    return this.prisma.emailTemplate.findUnique({ where: { id } });
  }

  async createTemplate(
    data: CreateEmailTemplateDto,
  ): Promise<EmailTemplateDto> {
    return this.prisma.emailTemplate.create({ data }); // Prisma expects { name, subject, html }
  }

  async updateTemplate(
    id: string,
    updateDto: UpdateEmailTemplateDto,
  ): Promise<EmailTemplateDto> {
    return this.prisma.emailTemplate.update({ where: { id }, data: updateDto });
  }

  async deleteTemplate(id: string): Promise<void> {
    await this.prisma.emailTemplate.delete({ where: { id } });
  }
}
