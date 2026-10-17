import { useState } from 'react';
import type { UseFormRegisterReturn } from 'react-hook-form';

type Props = { id: string; label: string; autoComplete: 'current-password' | 'new-password'; name: string; register: UseFormRegisterReturn; maxLength?: number };
export function PasswordField({ id, label, autoComplete, name, register, maxLength = 128 }: Props) {
  const [visible, setVisible] = useState(false);
  return <div className="field"><label htmlFor={id}>{label}</label><div className="password-wrap"><input id={id} type={visible ? 'text' : 'password'} autoComplete={autoComplete} maxLength={Math.max(128, maxLength)} {...register} name={name} /><button type="button" aria-label={visible ? 'Masquer le mot de passe' : 'Afficher le mot de passe'} aria-pressed={visible} onClick={() => setVisible(!visible)}>{visible ? 'Masquer' : 'Afficher'}</button></div></div>;
}
