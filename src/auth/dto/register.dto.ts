import { IsString, Matches, MinLength } from 'class-validator';

export class RegisterDto {
  @IsString()
  @Matches(/^[a-zA-Z0-9_]{3,32}$/, {
    message: 'Логин: 3–32 символа, латиница, цифры и подчёркивание',
  })
  username!: string;

  @IsString()
  @MinLength(8, { message: 'Пароль не короче 8 символов' })
  password!: string;

  @IsString()
  @MinLength(8, { message: 'Повторите пароль' })
  confirmPassword!: string;

  @IsString({ message: 'Подтвердите, что вы не робот' })
  @MinLength(1, { message: 'Подтвердите, что вы не робот' })
  captchaToken!: string;
}
