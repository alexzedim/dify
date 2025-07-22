import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useRouter, useSearchParams } from 'next/navigation'
import Button from '@/app/components/base/button'
import Input from '@/app/components/base/input'
import { login } from '@/service/common'
import Toast from '@/app/components/base/toast'
import { API_PREFIX } from '@/config'
import classNames from '@/utils/classnames'
import style from '../page.module.css'

type KeycloakAuthProps = {
  disabled?: boolean
}

export default function KeycloakAuth(props: KeycloakAuthProps) {
  const { t } = useTranslation()
  const router = useRouter()
  const searchParams = useSearchParams()
  const [isLoading, setIsLoading] = useState(false)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showForm, setShowForm] = useState(false)

  const handleKeycloakLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!username || !password) {
      Toast.notify({
        type: 'error',
        message: t('login.usernamePasswordRequired'),
      })
      return
    }

    setIsLoading(true)
    
    try {
      const response = await fetch(`${API_PREFIX}/keycloak/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username,
          password,
        }),
      })

      const result = await response.json()

      if (!response.ok) {
        throw new Error(result.error || 'Authentication failed')
      }

      if (result.access_token && result.refresh_token) {
        localStorage.setItem('console_token', result.access_token)
        localStorage.setItem('refresh_token', result.refresh_token)
        
        Toast.notify({
          type: 'success',
          message: t('login.keycloakLoginSuccess'),
        })
        
        router.replace('/apps')
      } else {
        throw new Error('Invalid response from server')
      }
    } catch (error) {
      console.error('Keycloak login error:', error)
      Toast.notify({
        type: 'error',
        message: error instanceof Error ? error.message : t('login.keycloakLoginFailed'),
      })
    } finally {
      setIsLoading(false)
    }
  }

  if (!showForm) {
    return (
      <div className='w-full'>
        <Button
          disabled={props.disabled}
          className='w-full'
          onClick={() => setShowForm(true)}
        >
          <>
            <span className={
              classNames(
                style.keycloakIcon,
                'mr-2 h-5 w-5',
              )
            } />
            <span className="truncate leading-normal">{t('login.withKeycloak')}</span>
          </>
        </Button>
      </div>
    )
  }

  return (
    <div className='w-full'>
      <form onSubmit={handleKeycloakLogin} className='space-y-4'>
        <div>
          <Input
            name="keycloak-username"
            type="text"
            placeholder={t('login.keycloakUsername')}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="appearance-none rounded-lg relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 focus:outline-none focus:ring-primary-500 focus:border-primary-500 focus:z-10"
          />
        </div>
        <div>
          <Input
            name="keycloak-password"
            type="password"
            placeholder={t('login.keycloakPassword')}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="appearance-none rounded-lg relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 focus:outline-none focus:ring-primary-500 focus:border-primary-500 focus:z-10"
          />
        </div>
        <div className='flex space-x-2'>
          <Button
            type="submit"
            disabled={props.disabled || isLoading}
            loading={isLoading}
            className='flex-1'
          >
            <>
              <span className={
                classNames(
                  style.keycloakIcon,
                  'mr-2 h-5 w-5',
                )
              } />
              <span className="truncate leading-normal">
                {isLoading ? t('login.keycloakLoggingIn') : t('login.keycloakSignIn')}
              </span>
            </>
          </Button>
          <Button
            type="button"
            variant="secondary"
            onClick={() => {
              setShowForm(false)
              setUsername('')
              setPassword('')
            }}
            className='px-4'
          >
            {t('login.cancel')}
          </Button>
        </div>
      </form>
    </div>
  )
}
