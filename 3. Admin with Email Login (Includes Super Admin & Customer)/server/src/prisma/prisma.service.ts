import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  private readonly logger = new Logger(PrismaService.name);
  private readonly isProduction: boolean;
  private queryCounter = 0;

  constructor(config: ConfigService) {
    const url = config.get<string>('DATABASE_URL');
    const nodeEnv = config.get<string>('NODE_ENV');
    const isProduction = nodeEnv === 'production';

    super({
      log: isProduction
        ? ['error', 'warn']
        : [
            {
              emit: 'event',
              level: 'query',
            },
            'info',
            'warn',
            'error',
          ],
      datasources: {
        db: {
          url,
        },
      },
      transactionOptions: {
        maxWait: 120000,
        timeout: 120000,
      },
      errorFormat: isProduction ? 'minimal' : 'pretty',
    });

    this.isProduction = isProduction;
  }

  async onModuleInit() {
    try {
      await this.$connect();
      this.logger.log('Database connected successfully');

      // Custom query logging with counter and context
      if (!this.isProduction) {
        // @ts-ignore
        this.$on('query' as any, (e: any) => {
          this.queryCounter++;
          const queryType = this.extractQueryType(e.query);
          const tableName = this.extractTableName(e.query);

          this.logger.log(
            `[Query #${this.queryCounter}] ${queryType} → ${tableName} (${e.duration}ms)`,
          );

          // Log full query for debugging (optional)
          if (e.duration > 100) {
            this.logger.debug(`Full query: ${e.query}`);
          }
        });
      }

      // Add query logging extension for slow queries and error tracking
      const config = new ConfigService();
      if (!this.isProduction || config.get<boolean>('LOG_SLOW_QUERIES')) {
        this.$extends({
          query: {
            $allModels: {
              async $allOperations({ operation, model, args, query }) {
                const startTime = Date.now();

                try {
                  const result = await query(args);
                  const duration = Date.now() - startTime;

                  // Only log slow queries (>1s)
                  if (duration > 1000) {
                    this.logger.warn(
                      `⚠️ Slow Query (${duration}ms) - ${model}.${operation}`,
                    );
                  }

                  return result;
                } catch (error) {
                  this.logger.error(
                    `❌ Query Failed - ${model}.${operation}: ${error.message}`,
                  );
                  throw error;
                }
              },
            },
          },
        });
      }
    } catch (error) {
      this.logger.error('Failed to connect to database', error);
      throw error;
    }
  }

  // Reset counter (useful for testing or per-request tracking)
  resetQueryCounter() {
    this.queryCounter = 0;
  }

  // Get current query count
  getQueryCount(): number {
    return this.queryCounter;
  }

  async onModuleDestroy() {
    await this.$disconnect();
    this.logger.log('Database disconnected');
  }

  // Helper for transactions with automatic retry
  async executeWithRetry<T>(fn: () => Promise<T>, maxRetries = 3): Promise<T> {
    let lastError: Error | undefined;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await fn();
      } catch (error) {
        lastError = error as Error;
        if (attempt < maxRetries) {
          this.logger.warn(
            `Transaction failed (attempt ${attempt}/${maxRetries}), retrying...`,
          );
          await new Promise((resolve) => setTimeout(resolve, attempt * 1000));
        }
      }
    }

    this.logger.error(`Transaction failed after ${maxRetries} attempts`);
    throw lastError!;
  }

  private extractQueryType(query: string): string {
    const queryUpper = query.trim().toUpperCase();
    if (queryUpper.startsWith('SELECT')) return 'SELECT';
    if (queryUpper.startsWith('INSERT')) return 'INSERT';
    if (queryUpper.startsWith('UPDATE')) return 'UPDATE';
    if (queryUpper.startsWith('DELETE')) return 'DELETE';
    if (queryUpper.includes('ON CONFLICT')) return 'UPSERT';
    return 'QUERY';
  }

  private extractTableName(query: string): string {
    // Extract table name from query
    const selectMatch = query.match(/FROM\s+"public"\."(\w+)"/i);
    const insertMatch = query.match(/INSERT INTO\s+"public"\."(\w+)"/i);
    const updateMatch = query.match(/UPDATE\s+"public"\."(\w+)"/i);
    const deleteMatch = query.match(/DELETE FROM\s+"public"\."(\w+)"/i);

    const match = selectMatch || insertMatch || updateMatch || deleteMatch;
    return match ? match[1] : 'Unknown';
  }
}
