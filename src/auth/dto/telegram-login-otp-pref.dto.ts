import { IsBoolean } from 'class-validator';

export class TelegramLoginOtpPrefDto {
  @IsBoolean()
  enabled!: boolean;
}
