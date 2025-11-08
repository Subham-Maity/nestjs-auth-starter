import {
  Body,
  Controller,
  Post,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { EmailService } from '../service';
import { SendTestEmailDto } from '../dto';

@ApiTags('Test Email')
@Controller('test-email')
export class TestEmailController {
  constructor(private readonly emailService: EmailService) {}

  @Post()
  @UsePipes(new ValidationPipe())
  @ApiOperation({ summary: 'Send a test email' })
  @ApiResponse({
    status: 200,
    description: 'Test email sent successfully',
    schema: {
      type: 'object',
      properties: {
        message: { type: 'string', example: 'Test email sent successfully' },
        to: { type: 'string', example: 'user@example.com' },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - validation failed',
  })
  @ApiResponse({
    status: 500,
    description: 'Failed to send email',
  })
  async sendTestEmail(@Body() sendTestEmailDto: SendTestEmailDto) {
    const { to, subject, body } = sendTestEmailDto;

    await this.emailService.sendDirectEmail(
      body,
      to,
      subject || 'Test Email from API',
    );

    return {
      message: 'Test email sent successfully',
      to,
    };
  }
}
