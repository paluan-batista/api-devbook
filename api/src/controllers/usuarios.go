package controllers

import (
	"api/src/auth"
	"api/src/database"
	"api/src/models"
	"api/src/repository"
	"api/src/response"
	"api/src/security"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
)

// CriarUsuario insere um usuário no database de dados
func CriarUsuario(w http.ResponseWriter, r *http.Request) {
	corpoRequest, erro := ioutil.ReadAll(r.Body)
	if erro != nil {
		response.Erro(w, http.StatusUnprocessableEntity, erro)
		return
	}

	var usuario models.Usuario
	if erro = json.Unmarshal(corpoRequest, &usuario); erro != nil {
		response.Erro(w, http.StatusBadRequest, erro)
		return
	}

	if erro = usuario.Preparar("cadastro"); erro != nil {
		response.Erro(w, http.StatusBadRequest, erro)
		return
	}

	db, erro := database.Conectar()
	if erro != nil {
		response.Erro(w, http.StatusInternalServerError, erro)
		return
	}
	defer db.Close()

	repository := repository.NovoRepositoryDeUsuarios(db)
	usuario.ID, erro = repository.Criar(usuario)
	if erro != nil {
		response.Erro(w, http.StatusInternalServerError, erro)
		return
	}

	response.JSON(w, http.StatusCreated, usuario)
}

// BuscarUsuarios busca todos os usuários salvos no database
func BuscarUsuarios(w http.ResponseWriter, r *http.Request) {
	nomeOuNick := strings.ToLower(r.URL.Query().Get("usuario"))
	db, erro := database.Conectar()
	if erro != nil {
		response.Erro(w, http.StatusInternalServerError, erro)
		return
	}
	defer db.Close()

	repository := repository.NovoRepositoryDeUsuarios(db)
	usuarios, erro := repository.Buscar(nomeOuNick)
	if erro != nil {
		response.Erro(w, http.StatusInternalServerError, erro)
		return
	}

	response.JSON(w, http.StatusOK, usuarios)
}

// BuscarUsuario busca um usuário salvo no database
func BuscarUsuario(w http.ResponseWriter, r *http.Request) {
	parametros := mux.Vars(r)

	usuarioID, erro := strconv.ParseUint(parametros["usuarioId"], 10, 64)
	if erro != nil {
		response.Erro(w, http.StatusBadRequest, erro)
		return
	}

	db, erro := database.Conectar()
	if erro != nil {
		response.Erro(w, http.StatusInternalServerError, erro)
		return
	}
	defer db.Close()

	repository := repository.NovoRepositoryDeUsuarios(db)
	usuario, erro := repository.BuscarPorID(usuarioID)
	if erro != nil {
		response.Erro(w, http.StatusInternalServerError, erro)
		return
	}

	response.JSON(w, http.StatusOK, usuario)
}

// AtualizarUsuario altera as informações de um usuário no database
func AtualizarUsuario(w http.ResponseWriter, r *http.Request) {
	parametros := mux.Vars(r)
	usuarioID, erro := strconv.ParseUint(parametros["usuarioId"], 10, 64)
	if erro != nil {
		response.Erro(w, http.StatusBadRequest, erro)
		return
	}

	usuarioIDNoToken, erro := auth.ExtrairUsuarioID(r)
	if erro != nil {
		response.Erro(w, http.StatusUnauthorized, erro)
		return
	}

	if usuarioID != usuarioIDNoToken {
		response.Erro(w, http.StatusForbidden, errors.New("não é possível atualizar um usuário que não seja o seu"))
		return
	}

	corpoRequisicao, erro := ioutil.ReadAll(r.Body)
	if erro != nil {
		response.Erro(w, http.StatusUnprocessableEntity, erro)
		return
	}

	var usuario models.Usuario
	if erro = json.Unmarshal(corpoRequisicao, &usuario); erro != nil {
		response.Erro(w, http.StatusBadRequest, erro)
		return
	}

	if erro = usuario.Preparar("edicao"); erro != nil {
		response.Erro(w, http.StatusBadRequest, erro)
		return
	}

	db, erro := database.Conectar()
	if erro != nil {
		response.Erro(w, http.StatusInternalServerError, erro)
		return
	}
	defer db.Close()

	repository := repository.NovoRepositoryDeUsuarios(db)
	if erro = repository.Atualizar(usuarioID, usuario); erro != nil {
		response.Erro(w, http.StatusInternalServerError, erro)
		return
	}

	response.JSON(w, http.StatusNoContent, nil)
}

// DeletarUsuario exclui as informações de um usuário no database
func DeletarUsuario(w http.ResponseWriter, r *http.Request) {
	parametros := mux.Vars(r)
	usuarioID, erro := strconv.ParseUint(parametros["usuarioId"], 10, 64)
	if erro != nil {
		response.Erro(w, http.StatusBadRequest, erro)
		return
	}

	usuarioIDNoToken, erro := auth.ExtrairUsuarioID(r)
	if erro != nil {
		response.Erro(w, http.StatusUnauthorized, erro)
		return
	}

	if usuarioID != usuarioIDNoToken {
		response.Erro(w, http.StatusForbidden, errors.New("não é possível deletar um usuário que não seja o seu"))
		return
	}

	db, erro := database.Conectar()
	if erro != nil {
		response.Erro(w, http.StatusInternalServerError, erro)
		return
	}
	defer db.Close()

	repository := repository.NovoRepositoryDeUsuarios(db)
	if erro = repository.Deletar(usuarioID); erro != nil {
		response.Erro(w, http.StatusInternalServerError, erro)
		return
	}

	response.JSON(w, http.StatusNoContent, nil)
}

// SeguirUsuario permite que um usuário siga outro
func SeguirUsuario(w http.ResponseWriter, r *http.Request) {
	seguidorID, erro := auth.ExtrairUsuarioID(r)
	if erro != nil {
		response.Erro(w, http.StatusUnauthorized, erro)
		return
	}

	parametros := mux.Vars(r)
	usuarioID, erro := strconv.ParseUint(parametros["usuarioId"], 10, 64)
	if erro != nil {
		response.Erro(w, http.StatusBadRequest, erro)
		return
	}

	if seguidorID == usuarioID {
		response.Erro(w, http.StatusForbidden, errors.New("não é possível seguir você mesmo"))
		return
	}

	db, erro := database.Conectar()
	if erro != nil {
		response.Erro(w, http.StatusInternalServerError, erro)
		return
	}
	defer db.Close()

	repository := repository.NovoRepositoryDeUsuarios(db)
	if erro = repository.Seguir(usuarioID, seguidorID); erro != nil {
		response.Erro(w, http.StatusInternalServerError, erro)
		return
	}

	response.JSON(w, http.StatusNoContent, nil)
}

// PararDeSeguirUsuario permite que um usuário pare de seguir outro
func PararDeSeguirUsuario(w http.ResponseWriter, r *http.Request) {
	seguidorID, erro := auth.ExtrairUsuarioID(r)
	if erro != nil {
		response.Erro(w, http.StatusUnauthorized, erro)
		return
	}

	parametros := mux.Vars(r)
	usuarioID, erro := strconv.ParseUint(parametros["usuarioId"], 10, 64)
	if erro != nil {
		response.Erro(w, http.StatusBadRequest, erro)
		return
	}

	if seguidorID == usuarioID {
		response.Erro(w, http.StatusForbidden, errors.New("não é possível parar de seguir você mesmo"))
		return
	}

	db, erro := database.Conectar()
	if erro != nil {
		response.Erro(w, http.StatusInternalServerError, erro)
		return
	}
	defer db.Close()

	repository := repository.NovoRepositoryDeUsuarios(db)
	if erro = repository.PararDeSeguir(usuarioID, seguidorID); erro != nil {
		response.Erro(w, http.StatusInternalServerError, erro)
		return
	}

	response.JSON(w, http.StatusNoContent, nil)
}

// BuscarSeguidores traz todos os seguidores de um usuário
func BuscarSeguidores(w http.ResponseWriter, r *http.Request) {
	parametros := mux.Vars(r)
	usuarioID, erro := strconv.ParseUint(parametros["usuarioId"], 10, 64)
	if erro != nil {
		response.Erro(w, http.StatusBadRequest, erro)
		return
	}

	db, erro := database.Conectar()
	if erro != nil {
		response.Erro(w, http.StatusInternalServerError, erro)
		return
	}
	defer db.Close()

	repository := repository.NovoRepositoryDeUsuarios(db)
	seguidores, erro := repository.BuscarSeguidores(usuarioID)
	if erro != nil {
		response.Erro(w, http.StatusInternalServerError, erro)
		return
	}

	response.JSON(w, http.StatusOK, seguidores)
}

// BuscarSeguindo traz todos os usuários que um determinado usuário está seguindo
func BuscarSeguindo(w http.ResponseWriter, r *http.Request) {
	parametros := mux.Vars(r)
	usuarioID, erro := strconv.ParseUint(parametros["usuarioId"], 10, 64)
	if erro != nil {
		response.Erro(w, http.StatusBadRequest, erro)
		return
	}

	db, erro := database.Conectar()
	if erro != nil {
		response.Erro(w, http.StatusInternalServerError, erro)
		return
	}
	defer db.Close()

	repository := repository.NovoRepositoryDeUsuarios(db)
	usuarios, erro := repository.BuscarSeguindo(usuarioID)
	if erro != nil {
		response.Erro(w, http.StatusInternalServerError, erro)
		return
	}

	response.JSON(w, http.StatusOK, usuarios)
}

// AtualizarSenha permite alterar a senha de um usuário
func AtualizarSenha(w http.ResponseWriter, r *http.Request) {
	usuarioIDNoToken, erro := auth.ExtrairUsuarioID(r)
	if erro != nil {
		response.Erro(w, http.StatusUnauthorized, erro)
		return
	}

	parametros := mux.Vars(r)
	usuarioID, erro := strconv.ParseUint(parametros["usuarioId"], 10, 64)
	if erro != nil {
		response.Erro(w, http.StatusBadRequest, erro)
		return
	}

	if usuarioIDNoToken != usuarioID {
		response.Erro(w, http.StatusForbidden, errors.New("não é possível atualizar a senha de um usuário que não seja o seu"))
		return
	}

	corpoRequisicao, erro := ioutil.ReadAll(r.Body)

	if erro != nil {
		response.Erro(w, http.StatusExpectationFailed, erro)
	}
	var senha models.Senha
	if erro = json.Unmarshal(corpoRequisicao, &senha); erro != nil {
		response.Erro(w, http.StatusBadRequest, erro)
		return
	}

	db, erro := database.Conectar()
	if erro != nil {
		response.Erro(w, http.StatusInternalServerError, erro)
		return
	}
	defer db.Close()

	repository := repository.NovoRepositoryDeUsuarios(db)
	senhaSalvaNodatabase, erro := repository.BuscarSenha(usuarioID)
	if erro != nil {
		response.Erro(w, http.StatusInternalServerError, erro)
		return
	}

	if erro = security.VerificarSenha(senhaSalvaNodatabase, senha.Atual); erro != nil {
		response.Erro(w, http.StatusUnauthorized, errors.New("a senha atual não condiz com a que está salva no database"))
		return
	}

	senhaComHash, erro := security.Hash(senha.Nova)
	if erro != nil {
		response.Erro(w, http.StatusBadRequest, erro)
		return
	}

	if erro = repository.AtualizarSenha(usuarioID, string(senhaComHash)); erro != nil {
		response.Erro(w, http.StatusInternalServerError, erro)
		return
	}

	response.JSON(w, http.StatusNoContent, nil)
}
