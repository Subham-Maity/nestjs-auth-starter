import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsString } from 'class-validator';

export class UpdateEmailTemplateDto {
  @ApiProperty({
    description: 'Unique name of the email template',
    example: 'OrderConfirmation',
    required: false,
  })
  @IsString()
  @IsOptional()
  name?: string;

  @ApiProperty({
    description: 'Subject of the email',
    example: 'Your Order Confirmation',
    required: false,
  })
  @IsString()
  @IsOptional()
  subject?: string;

  @ApiProperty({
    description: 'HTML content with placeholders',
    example: '<p>Hello {{userName}}, your order {{orderId}} is confirmed.</p>',
    required: false,
  })
  @IsString()
  @IsOptional()
  html?: string;
}
