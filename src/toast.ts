export type ToastType = 'success' | 'error' | 'loading' | 'info';

export interface ToastOptions {
  id?: string;
  duration?: number; // ms
}

export interface Toast {
  id: string;
  type: ToastType;
  message: string;
  duration: number;
}

type Listener = (toasts: Toast[]) => void;

let toasts: Toast[] = [];
let listeners: Listener[] = [];

function emit() {
  listeners.forEach(l => l([...toasts]));
}

export const toast: any = {
  success: (msg: string, opts?: ToastOptions) => addToast('success', msg, opts),
  error: (msg: string, opts?: ToastOptions) => addToast('error', msg, opts),
  loading: (msg: string, opts?: ToastOptions) => addToast('loading', msg, opts),
  info: (msg: string, opts?: ToastOptions) => addToast('info', msg, opts),
  dismiss: (id: string) => {
    toasts = toasts.filter(t => t.id !== id);
    emit();
  },
  subscribe: (listener: Listener) => {
    listeners.push(listener);
    return () => {
      listeners = listeners.filter(l => l !== listener);
    };
  }
};

function addToast(type: ToastType, message: string, opts?: ToastOptions) {
  const id = opts?.id || Math.random().toString(36).substring(2, 9);
  
  const existingIndex = toasts.findIndex(t => t.id === id);
  if (existingIndex >= 0) {
    toasts[existingIndex] = { ...toasts[existingIndex], type, message };
  } else {
    toasts.push({ id, type, message, duration: opts?.duration ?? (type === 'loading' ? Infinity : 4000) });
  }
  
  emit();

  const duration = opts?.duration ?? (type === 'loading' ? Infinity : 4000);
  if (duration !== Infinity) {
    setTimeout(() => {
      toast.dismiss(id);
    }, duration);
  }
  return id;
}

toast.promise = async <T>(
  promise: Promise<T> | (() => Promise<T>),
  msgs: { loading: string; success: string | ((data: T) => string); error: string | ((err: any) => string) }
) => {
  const id = toast.loading(msgs.loading);
  try {
    const p = typeof promise === 'function' ? promise() : promise;
    const res = await p;
    toast.success(typeof msgs.success === 'function' ? msgs.success(res) : msgs.success, { id });
    return res;
  } catch (err) {
    toast.error(typeof msgs.error === 'function' ? msgs.error(err) : msgs.error, { id });
    throw err;
  }
};
