import { IsString, MinLength } from 'class-validator';

export class SiteAdminLoginDto {
  @IsString()
  @MinLength(1)
  login!: string;

  @IsString()
  @MinLength(1)
  password!: string;
}
