import '@testing-library/jest-dom/vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { LiveReplaySwitcher } from './LiveReplaySwitcher';

describe('LiveReplaySwitcher', () => {
  it('renders both contexts with the active one marked', () => {
    render(<LiveReplaySwitcher mode="replay" onChange={() => {}} />);

    const group = screen.getByRole('radiogroup', { name: /konteks data/i });
    expect(group).toBeInTheDocument();
    expect(screen.getByRole('radio', { name: /replay/i })).toHaveAttribute('aria-checked', 'true');
    expect(screen.getByRole('radio', { name: /live/i })).toHaveAttribute('aria-checked', 'false');
  });

  it('calls onChange when switching context', () => {
    const onChange = vi.fn();
    render(<LiveReplaySwitcher mode="replay" onChange={onChange} />);

    fireEvent.click(screen.getByRole('radio', { name: /live/i }));
    expect(onChange).toHaveBeenCalledWith('live');
  });

  it('shows loading, error, and empty states', () => {
    const { rerender } = render(<LiveReplaySwitcher mode="live" onChange={() => {}} status="loading" />);
    expect(screen.getByRole('status')).toHaveTextContent(/memuat konteks/i);

    rerender(<LiveReplaySwitcher mode="live" onChange={() => {}} status="error" errorMessage="putus" />);
    expect(screen.getByRole('alert')).toHaveTextContent(/gagal memuat konteks.*putus/i);

    rerender(<LiveReplaySwitcher mode="live" onChange={() => {}} status="empty" />);
    expect(screen.getByRole('status')).toHaveTextContent(/belum ada meta-alert/i);
  });

  it('menegaskan konteks aktif lewat keterangan dan gaya', () => {
    const { rerender } = render(<LiveReplaySwitcher mode="live" onChange={() => {}} />);
    expect(screen.getByText(/menampilkan: live/i)).toBeInTheDocument();
    expect(screen.getByRole('radio', { name: /^live/i })).toHaveClass('switcher-active');

    rerender(<LiveReplaySwitcher mode="replay" onChange={() => {}} />);
    expect(screen.getByText(/menampilkan: replay/i)).toBeInTheDocument();
    expect(screen.getByRole('radio', { name: /^replay/i })).toHaveClass('switcher-active');
  });

  it('disables switching while disabled', () => {
    const onChange = vi.fn();
    render(<LiveReplaySwitcher mode="replay" onChange={onChange} disabled />);

    fireEvent.click(screen.getByRole('radio', { name: /live/i }));
    expect(onChange).not.toHaveBeenCalled();
  });
});
