import { ApiProperty } from '@nestjs/swagger';

export class EmailTemplateDto {
  @ApiProperty({
    description: 'ID of the email template',
    example: 'clabc123',
  })
  id?: string;

  @ApiProperty({
    description: 'Unique name of the email template',
    example: 'OrderConfirmation',
  })
  name: string;

  @ApiProperty({
    description: 'Subject of the email',
    example: 'Your Order Confirmation',
  })
  subject: string;

  @ApiProperty({
    description: 'HTML content with placeholders',
    example: '<p>Hello {{userName}}, your order {{orderId}} is confirmed.</p>',
  })
  html: string;

  @ApiProperty({
    description: 'Creation timestamp',
    example: '2023-01-01T00:00:00Z',
  })
  createdAt?: Date;

  @ApiProperty({
    description: 'Last update timestamp',
    example: '2023-01-01T00:00:00Z',
  })
  updatedAt?: Date;
}
