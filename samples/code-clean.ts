import { useState } from 'react';

type Props = { title: string; items: string[]; onSelect: (i: number) => void };

export const Panel = ({ title, items, onSelect }: Props) => {
  const [open, setOpen] = useState<boolean>(false);
  // 👨‍🍳 chef mode: emoji joiners must not read as hidden characters
  return (
    <div className={open ? 'panel open' : 'panel'}>
      <h2>{title}</h2>
      {items.map((it, i) => <button key={i} onClick={() => onSelect(i)}>{it}</button>)}
    </div>
  );
};
