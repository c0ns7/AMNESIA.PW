import { IsInt, Min } from 'class-validator';

export class CheckTopupDto {
  @IsInt()
  @Min(1)
  paymentId!: number;
}
