import { IsString, Matches, MinLength } from 'class-validator';

export class CompletePasswordResetDto {
  @IsString()
  @MinLength(32)
  challengeId!: string;

  @IsString()
  @Matches(/^\d{6}$/, { message: 'Код: 6 цифр' })
  code!: string;

  @IsString()
  @MinLength(6, { message: 'Новый пароль: минимум 6 символов' })
  newPassword!: string;

  @IsString()
  @MinLength(1, { message: 'Подтвердите новый пароль' })
  confirmPassword!: string;
}
