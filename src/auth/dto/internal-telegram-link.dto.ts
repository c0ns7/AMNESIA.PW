import { IsOptional, IsString, MinLength } from 'class-validator';

export class InternalTelegramLinkDto {
  @IsString()
  @MinLength(16)
  token!: string;

  @IsString()
  @MinLength(1)
  telegramId!: string;

  @IsOptional()
  @IsString()
  telegramUsername?: string;
}
