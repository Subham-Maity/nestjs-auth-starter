import * as Handlebars from 'handlebars';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Resend } from 'resend';
import { PrismaService } from '../../prisma';

@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);
  private readonly resend: Resend;
  private readonly mainEmail: any;

  constructor(
    private readonly configService: ConfigService,
    private readonly prisma: PrismaService,
  ) {
    const apiKey = this.configService.get<string>('RESEND_API_KEY');
    this.mainEmail = this.configService.get<string>('MAIN_EMAIL_ADDRESS');

    // Debug configuration
    this.logger.debug('=== Email Service Configuration ===');
    this.logger.debug(`RESEND_API_KEY exists: ${!!apiKey}`);
    this.logger.debug(`RESEND_API_KEY length: ${apiKey?.length || 0}`);
    this.logger.debug(`MAIN_EMAIL_ADDRESS: ${this.mainEmail}`);
    this.logger.debug('===================================');

    if (!apiKey) {
      this.logger.error('RESEND_API_KEY is not configured!');
      throw new Error('RESEND_API_KEY is missing');
    }

    if (!this.mainEmail) {
      this.logger.error('MAIN_EMAIL_ADDRESS is not configured!');
      throw new Error('MAIN_EMAIL_ADDRESS is missing');
    }

    this.resend = new Resend(apiKey);
    this.logger.log('Email Service initialized successfully');
  }

  async sendEmail(
    templateName: string,
    props: Record<string, any>,
    to: string,
  ): Promise<void> {
    this.logger.debug('=== Sending Template Email ===');
    this.logger.debug(`Template Name: ${templateName}`);
    this.logger.debug(`Recipient: ${to}`);
    this.logger.debug(`Props: ${JSON.stringify(props)}`);

    const template = await this.prisma.emailTemplate.findUnique({
      where: { name: templateName },
    });

    if (!template) {
      this.logger.error(`Template not found: ${templateName}`);
      throw new Error(`Template ${templateName} not found`);
    }

    this.logger.debug(`Template found: ${template.name}`);
    this.logger.debug(`Subject: ${template.subject}`);

    const compiledTemplate = Handlebars.compile(template.html);
    const html = compiledTemplate(props);

    this.logger.debug(`HTML compiled successfully`);

    try {
      this.logger.debug('Attempting to send email via Resend...');
      const response = await this.resend.emails.send({
        from: this.mainEmail,
        to,
        subject: template.subject,
        html,
      });

      this.logger.debug(`Resend Response: ${JSON.stringify(response)}`);
      this.logger.log(`Email sent successfully to ${to}`);
    } catch (error) {
      this.logger.error(`Failed to send email: ${error.message}`, error.stack);
      throw new Error(`Failed to send email: ${error.message}`);
    }
  }

  async sendDirectEmail(
    body: string,
    to: string,
    subject: string = 'Message from Admin',
  ): Promise<void> {
    this.logger.debug('=== Sending Direct Email ===');
    this.logger.debug(`From: ${this.mainEmail}`);
    this.logger.debug(`To: ${to}`);
    this.logger.debug(`Subject: ${subject}`);
    this.logger.debug(`Body length: ${body.length} characters`);
    this.logger.debug(`Body preview: ${body.substring(0, 100)}...`);

    try {
      this.logger.debug('Attempting to send email via Resend...');

      const emailPayload = {
        from: this.mainEmail,
        to,
        subject,
        text: body,
      };

      this.logger.debug(`Email Payload: ${JSON.stringify(emailPayload)}`);

      const response = await this.resend.emails.send(emailPayload);

      this.logger.debug(`Resend Response: ${JSON.stringify(response)}`);

      if (response.data?.id) {
        this.logger.log(
          `✅ Email sent successfully! Email ID: ${response.data.id}`,
        );
      } else {
        this.logger.warn(`Email sent but no ID returned`);
      }

      this.logger.debug(`Full response: ${JSON.stringify(response)}`);

      this.logger.debug('=== Email Send Complete ===');
    } catch (error) {
      this.logger.error('=== Email Send Failed ===');
      this.logger.error(`Error Type: ${error.constructor.name}`);
      this.logger.error(`Error Message: ${error.message}`);
      this.logger.error(`Error Stack: ${error.stack}`);

      if (error.response) {
        this.logger.error(`API Response: ${JSON.stringify(error.response)}`);
      }

      if (error.statusCode) {
        this.logger.error(`Status Code: ${error.statusCode}`);
      }

      throw new Error(`Failed to send plain email: ${error.message}`);
    }
  }
}
