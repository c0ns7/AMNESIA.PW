import { IsString, MaxLength, MinLength } from 'class-validator';

export class ActivatePromoDto {
  @IsString()
  @MinLength(1, { message: 'Введите промокод' })
  @MaxLength(64, { message: 'Промокод слишком длинный' })
  code!: string;
}
