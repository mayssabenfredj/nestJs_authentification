import { IsNotEmpty, IsEmail} from 'class-validator';

export class EmailAuthDto {
  @IsNotEmpty()
  @IsEmail()
  public email: string;

}
