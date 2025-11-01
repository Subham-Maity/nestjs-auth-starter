import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class CreateEmailTemplateDto {
  @ApiProperty({
    description: 'Unique name of the email template',
    example: 'OrderConfirmation',
  })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiProperty({
    description: 'Subject of the email',
    example: 'Your Order Confirmation',
  })
  @IsString()
  @IsNotEmpty()
  subject: string;

  @ApiProperty({
    description: 'HTML content with placeholders',
    example: '<p>Hello {{userName}}, your order {{orderId}} is confirmed.</p>',
  })
  @IsString()
  @IsNotEmpty()
  html: string;
}
