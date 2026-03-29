import { IsString, MaxLength, MinLength } from 'class-validator';

export class RemoveDeviceDto {
  @IsString()
  @MinLength(1, { message: 'Не указано устройство' })
  @MaxLength(512)
  hwid!: string;
}
