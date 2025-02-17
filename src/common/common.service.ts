import {
  BadRequestException,
  ConflictException,
  Injectable,
  InternalServerErrorException,
  Logger,
  LoggerService,
  NotFoundException
} from '@nestjs/common';
import { Dictionary, EntityManager } from '@mikro-orm/core';
import { validate } from 'class-validator';
import slugify from 'slugify';
import { IMessage } from './interfaces/message.interface';
import { v4 } from 'uuid';

@Injectable()
export class CommonService {
  private readonly loggerService: LoggerService;

  constructor(private readonly em: EntityManager) {
    this.loggerService = new Logger(CommonService.name);
  }

  /**
   * Check Entity Existence
   *
   * Checks if a findOne query didn't return null or undefined
   */
  public checkEntityExistence<T extends Dictionary>(
    entity: T | null | undefined,
    name: string,
  ): void {
    if (!entity) {
      throw new NotFoundException(`${name} not found`);
    }
  }

  /**
   * Save Entity
   *
   * Validates, saves and flushes entities into the DB
   */
  public async saveEntity<T extends Dictionary>(
    entity: T,
    isNew = false,
  ): Promise<void> {
    await this.validateEntity(entity);

    if (isNew) {
      this.em.persist(entity);
    }

    await this.throwDuplicateError(this.em.flush());
  }

  /**
   * Remove Entity
   *
   * Removes an entities from the DB.
   */
  public async removeEntity<T extends Dictionary>(entity: T): Promise<void> {
    await this.throwInternalError(this.em.removeAndFlush(entity));
  }

  /**
   * Throw Duplicate Error
   *
   * Checks is an error is of the code 23505, PostgreSQL's duplicate value error,
   * and throws a conflict exception
   */
  public async throwDuplicateError<T>(
    promise: Promise<T>,
    message?: string,
  ): Promise<T> {
    try {
      return await promise;
    } catch (error) {
      this.loggerService.error(error);

      if (error.code === '23505') {
        throw new ConflictException(message ?? 'Duplicated value in database');
      }

      throw new BadRequestException(error.message);
    }
  }

  /**
   * Throw Internal Error
   *
   * Function to abstract throwing internal server exception
   */
  public async throwInternalError<T>(promise: Promise<T>): Promise<T> {
    try {
      return await promise;
    } catch (error) {
      this.loggerService.error(error);
      throw new InternalServerErrorException(error);
    }
  }

  /**
   * Validate Entity
   *
   * Validates an entities with the class-validator library
   */
  public async validateEntity(entity: Dictionary): Promise<void> {
    const errors = await validate(entity);

    if (errors.length > 0) {
      const messages = errors
        .map((error) => Object.values(error.constraints))
        .join(',\n');
      throw new BadRequestException(messages);
    }
  }

  /**
   * Format Name
   *
   * Takes a string trims it and capitalizes every word
   */
  public formatName(title: string): string {
    return title
      .trim()
      .replace(/\n/g, ' ')
      .replace(/\s\s+/g, ' ')
      .replace(/\w\S*/g, (w) => w.replace(/^\w/, (l) => l.toUpperCase()));
  }

  /**
   * Generate Point Slug
   *
   * Takes a string and generates a slug with dots as word separators
   */
  public generatePointSlug(str: string): string {
    return slugify(str, { lower: true, replacement: '.', remove: /['_\.\-]/g });
  }

  public generateMessage(message: string): IMessage {
    return { id: v4(), message };
  }
}
