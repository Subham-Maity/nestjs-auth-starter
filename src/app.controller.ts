import { Controller, Get, HttpCode, HttpStatus, Res } from '@nestjs/common';
import { AppService } from './app.service';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import {} from '@nestjs/common';
import { Response } from 'express';

@ApiTags('Entry Point')
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Entry Point',
    description:
      'https://..../xam <- You can use this link to check if the server is running.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Returns a simple message.',
  })
  @Get()
  getHello(): string {
    return this.appService.getHello();
  }

  @Get('/doc')
  redoc(@Res() res: Response) {
    res.send(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>API Docs - Redoc</title>
          <meta charset="utf-8"/>
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
        </head>
        <body>
          <redoc spec-url="/swagger.json"></redoc>
        </body>
      </html>
    `);
  }
}
