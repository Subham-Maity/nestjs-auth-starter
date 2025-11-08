// src/common/types/pagination-response.type.ts
export type PaginatedResponse<T> = {
  data: T[];
  meta: {
    total: number;
    page: number;
    lastPage: number;
  };
};
