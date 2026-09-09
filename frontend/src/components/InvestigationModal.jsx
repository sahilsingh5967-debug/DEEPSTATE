import React, { useEffect } from 'react';
import { X, Layers } from 'lucide-react';

export default function InvestigationModal({
  isOpen,
  onClose,
  title,
  subtitle,
  children
}) {
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(37,37,37,0.32)',
        backdropFilter: 'blur(2px)',
        zIndex: 1000,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '24px',
        boxSizing: 'border-box'
      }}
    >
      <div
        className="animate-modal-in"
        onClick={(e) => e.stopPropagation()}
        style={{
          backgroundColor: '#FFFDF8',
          border: '1px solid #D8D4C8',
          borderRadius: '12px',
          boxShadow: '0 16px 50px rgba(30, 30, 20, 0.18)',
          width: '720px',
          maxWidth: 'calc(100vw - 48px)',
          maxHeight: '80vh',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden'
        }}
      >
        {/* Modal Header */}
        <div style={{
          padding: '20px 24px',
          borderBottom: '1px solid #EDEAE1',
          display: 'flex',
          alignItems: 'flex-start',
          justifyContent: 'space-between',
          backgroundColor: '#FFFFFF'
        }}>
          <div>
            <div style={{
              fontSize: '11px',
              fontWeight: '700',
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
              color: '#9A7618',
              marginBottom: '4px'
            }}>
              DEEPSTATE INVESTIGATION WORKSPACE
            </div>
            <h3 style={{ margin: 0, fontSize: '18px', fontWeight: '700', color: '#252525' }}>
              {title}
            </h3>
            {subtitle && (
              <p style={{ margin: '4px 0 0', fontSize: '13px', color: '#66645D' }}>
                {subtitle}
              </p>
            )}
          </div>

          <button
            type="button"
            onClick={onClose}
            style={{
              width: '32px',
              height: '32px',
              borderRadius: '6px',
              backgroundColor: 'transparent',
              border: 'none',
              color: '#66645D',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'background-color 0.15s ease'
            }}
            onMouseOver={(e) => e.currentTarget.style.backgroundColor = '#EDEAE1'}
            onMouseOut={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
          >
            <X style={{ width: '18px', height: '18px' }} />
          </button>
        </div>

        {/* Modal Body */}
        <div style={{
          padding: '24px',
          overflowY: 'auto',
          display: 'flex',
          flexDirection: 'column',
          gap: '20px'
        }}>
          {children}
        </div>

        {/* Modal Footer */}
        <div style={{
          padding: '14px 24px',
          borderTop: '1px solid #EDEAE1',
          display: 'flex',
          justifyContent: 'flex-end',
          backgroundColor: '#FFFFFF'
        }}>
          <button
            type="button"
            onClick={onClose}
            style={{
              height: '36px',
              padding: '0 18px',
              borderRadius: '6px',
              backgroundColor: '#252525',
              color: '#FFFFFF',
              fontSize: '13px',
              fontWeight: '600',
              border: 'none',
              cursor: 'pointer',
              transition: 'background-color 0.15s ease'
            }}
            onMouseOver={(e) => e.currentTarget.style.backgroundColor = '#404040'}
            onMouseOut={(e) => e.currentTarget.style.backgroundColor = '#252525'}
          >
            CLOSE
          </button>
        </div>
      </div>
    </div>
  );
}
