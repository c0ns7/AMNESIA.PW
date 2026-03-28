import { Controller, Get, Query, Res } from '@nestjs/common';
import { Response } from 'express';
import { SubscriptionLinkService } from './subscription-link.service';

@Controller('api/subscription')
export class SubscriptionController {
  constructor(private readonly links: SubscriptionLinkService) {}

  @Get('proxy')
  proxy(@Query('t') t: string, @Res() res: Response) {
    const url = this.links.verifyTokenAndGetUrl(t);
    if (!url) {
      return res
        .status(400)
        .type('text/plain; charset=utf-8')
        .send('Недействительная ссылка');
    }
    return res.redirect(302, url);
  }
}
