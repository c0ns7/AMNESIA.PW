import { IsIn, IsNumber, Max, Min } from 'class-validator';

export class CreateTopupDto {
  @IsNumber()
  @Min(10, { message: 'Минимальная сумма пополнения — 10 ₽' })
  @Max(50000, { message: 'Слишком большая сумма пополнения' })
  amount!: number;

  @IsIn(['sbp', 'card'], { message: 'Метод оплаты должен быть sbp или card' })
  method!: 'sbp' | 'card';
}
