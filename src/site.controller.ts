import { Controller, Get, Res } from '@nestjs/common';
import { join } from 'path';
import { Response } from 'express';

@Controller()
export class SiteController {
  private readonly publicDir = join(__dirname, '..', 'public');

  @Get('401')
  page401(@Res() res: Response) {
    return res.status(401).sendFile(join(this.publicDir, '401.html'));
  }

  @Get('403')
  page403(@Res() res: Response) {
    return res.status(403).sendFile(join(this.publicDir, '403.html'));
  }

  @Get('404')
  page404(@Res() res: Response) {
    return res.status(404).sendFile(join(this.publicDir, '404.html'));
  }

  @Get('500')
  page500(@Res() res: Response) {
    return res.status(500).sendFile(join(this.publicDir, '500.html'));
  }

  @Get('503')
  page503(@Res() res: Response) {
    return res.status(503).sendFile(join(this.publicDir, '503.html'));
  }

  @Get('terms')
  pageTerms(@Res() res: Response) {
    return res.sendFile(join(this.publicDir, 'terms', 'index.html'));
  }

  @Get('privacy')
  pagePrivacy(@Res() res: Response) {
    return res.sendFile(join(this.publicDir, 'privacy', 'index.html'));
  }

  @Get('support')
  pageSupport(@Res() res: Response) {
    return res.sendFile(join(this.publicDir, 'support', 'index.html'));
  }
}
