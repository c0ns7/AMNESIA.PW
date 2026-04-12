import { IsString, Matches, MinLength } from 'class-validator';

export class SiteAdminVerifyOtpDto {
  @IsString()
  @MinLength(16)
  sessionId!: string;

  @IsString()
  @Matches(/^\d{6}$/, { message: 'Код — 6 цифр' })
  code!: string;
}
