import { IsString, Matches, MinLength } from 'class-validator';

export class LoginDto {
  @IsString()
  @Matches(/^[a-zA-Z0-9_]{3,32}$/, {
    message: 'Логин: 3–32 символа, латиница, цифры и подчёркивание',
  })
  username!: string;

  @IsString()
  @MinLength(1, { message: 'Введите пароль' })
  password!: string;
}
