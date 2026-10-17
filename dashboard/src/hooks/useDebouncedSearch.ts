import { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';

export function useDebouncedSearch(paramName = 'search', delay = 300) {
  const [searchParams, setSearchParams] = useSearchParams();
  const urlValue = searchParams.get(paramName) || '';
  const [localValue, setLocalValue] = useState(urlValue);

  // Sinkronkan URL ke state lokal bila URL berubah dari luar
  useEffect(() => {
    setLocalValue(urlValue);
  }, [urlValue]);

  // Debounce nilai lokal ke URL
  useEffect(() => {
    const timer = setTimeout(() => {
      if (localValue !== urlValue) {
        const params = new URLSearchParams(searchParams);
        if (localValue) params.set(paramName, localValue);
        else params.delete(paramName);
        params.set('page', '1');
        setSearchParams(params);
      }
    }, delay);
    return () => clearTimeout(timer);
  }, [localValue, urlValue, delay, paramName, searchParams, setSearchParams]);

  return { value: localValue, onChange: setLocalValue };
}
