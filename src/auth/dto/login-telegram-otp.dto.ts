import { IsString, Matches, MinLength } from 'class-validator';

export class LoginTelegramOtpDto {
  @IsString()
  @MinLength(32)
  challengeId!: string;

  @IsString()
  @Matches(/^\d{6}$/, { message: 'Код: 6 цифр' })
  code!: string;
}
