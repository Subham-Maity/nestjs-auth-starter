import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  Put,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { EmailTemplateService } from '../service';
import {
  CreateEmailTemplateDto,
  EmailTemplateDto,
  UpdateEmailTemplateDto,
} from '../dto';

@ApiTags('Email Templates')
@Controller('email-templates')
export class EmailTemplateController {
  constructor(private readonly emailTemplateService: EmailTemplateService) {}

  @Get()
  @ApiOperation({ summary: 'Get all email templates' })
  @ApiResponse({
    status: 200,
    description: 'List of email templates',
    type: [EmailTemplateDto],
  })
  async getAllTemplates(): Promise<EmailTemplateDto[]> {
    return this.emailTemplateService.getAllTemplates();
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get email template by ID' })
  @ApiResponse({
    status: 200,
    description: 'Email template details',
    type: EmailTemplateDto,
  })
  async getTemplateById(@Param('id') id: string) {
    return this.emailTemplateService.getTemplateById(id);
  }

  @Post()
  @UsePipes(new ValidationPipe())
  @ApiOperation({ summary: 'Create a new email template' })
  @ApiResponse({
    status: 201,
    description: 'Email template created',
    type: EmailTemplateDto,
  })
  async createEmailTemplate(
    @Body() createDto: CreateEmailTemplateDto, // Use DTO for validation
  ) {
    return this.emailTemplateService.createTemplate(createDto); // Pass directly
  }

  @Put(':id')
  @UsePipes(new ValidationPipe())
  @ApiOperation({ summary: 'Update an existing email template' })
  @ApiResponse({
    status: 200,
    description: 'Email template updated',
    type: EmailTemplateDto,
  })
  async updateTemplate(
    @Param('id') id: string,
    @Body() updateDto: UpdateEmailTemplateDto,
  ): Promise<EmailTemplateDto> {
    return this.emailTemplateService.updateTemplate(id, updateDto);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Delete an email template' })
  @ApiResponse({ status: 204, description: 'Email template deleted' })
  async deleteTemplate(@Param('id') id: string): Promise<void> {
    return this.emailTemplateService.deleteTemplate(id);
  }
}
