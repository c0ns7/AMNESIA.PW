import { Controller, Get } from '@nestjs/common';
import { RemnawaveService } from './remnawave.service';

@Controller()
export class RemnawaveController {
  constructor(private readonly remnawaveService: RemnawaveService) {}

  @Get('api/infra')
  getInfrastructure(): Promise<unknown> {
    return this.remnawaveService.getInfrastructure();
  }
}
