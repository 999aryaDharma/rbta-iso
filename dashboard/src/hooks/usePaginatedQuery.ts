import { useQuery, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import { useCallback, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';

export function usePaginatedQuery<T extends { total: number }>({
  queryKeyBase,
  queryFn,
  pageSize = 20,
  extraParams,
}: {
  queryKeyBase: string;
  queryFn: (params: { page: number; page_size: number } & Record<string, any>) => Promise<T>;
  pageSize?: number;
  extraParams?: Record<string, any>;
}) {
  const [searchParams, setSearchParams] = useSearchParams();
  const queryClient = useQueryClient();
  const page = Number(searchParams.get('page') || 1);

  const queryKey = [queryKeyBase, page, pageSize, ...(extraParams ? [extraParams] : [])];

  const { data, isPlaceholderData, isFetching } = useQuery({
    queryKey,
    queryFn: () => queryFn({ page, page_size: pageSize, ...extraParams }),
    placeholderData: keepPreviousData,
    staleTime: 5000,
  });

  const totalPages = data ? Math.ceil(data.total / pageSize) || 1 : 1;

  // Prefetch halaman berikutnya
  useEffect(() => {
    if (data && page < totalPages) {
      const nextKey = [queryKeyBase, page + 1, pageSize, ...(extraParams ? [extraParams] : [])];
      queryClient.prefetchQuery({
        queryKey: nextKey,
        queryFn: () => queryFn({ page: page + 1, page_size: pageSize, ...extraParams }),
        staleTime: 5000,
      });
    }
  }, [data, page, totalPages, queryClient, queryKeyBase, pageSize, extraParams, queryFn]);

  const setPage = useCallback((newPage: number) => {
    const params = new URLSearchParams(searchParams);
    params.set('page', String(newPage));
    setSearchParams(params);
  }, [searchParams, setSearchParams]);

  return {
    data,
    page,
    totalPages,
    totalCount: data?.total ?? 0,
    setPage,
    isPlaceholderData,
    isFetching,
  };
}
