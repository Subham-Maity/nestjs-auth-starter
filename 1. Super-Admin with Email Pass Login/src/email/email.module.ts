import { Global, Module } from '@nestjs/common';
import { EmailService, EmailTemplateService } from './service';
import { EmailTemplateController, TestEmailController } from './controller';

@Global()
@Module({
  controllers: [EmailTemplateController, TestEmailController],
  providers: [EmailService, EmailTemplateService],
  exports: [EmailService, EmailTemplateService],
})
export class EmailModule {}
