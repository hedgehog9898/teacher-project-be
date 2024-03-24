import { ICredentials } from './credentials.interface';

export interface IUser {
  id: number;
  name: string;
  username: string;
  email: string;
  credentials: ICredentials;
  password: string;
  confirmed: boolean;
  createdAt: Date;
  updatedAt: Date;
}
