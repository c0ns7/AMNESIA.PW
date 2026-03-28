import { IsString, MinLength } from 'class-validator';

export class ChangePasswordDto {
  @IsString()
  @MinLength(1, { message: 'Введите текущий пароль' })
  currentPassword!: string;

  @IsString()
  @MinLength(6, { message: 'Новый пароль: минимум 6 символов' })
  newPassword!: string;

  @IsString()
  @MinLength(1, { message: 'Подтвердите новый пароль' })
  confirmPassword!: string;
}
